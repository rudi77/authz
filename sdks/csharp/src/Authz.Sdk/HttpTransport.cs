using System.Net;
using System.Text;
using System.Text.Json;

namespace Authz.Sdk;

/// <summary>
/// Shared HTTP layer of both clients: JSON in/out, API key header, per-attempt
/// timeout and retry with exponential backoff on transport errors and 5xx.
/// 4xx is never retried.
/// </summary>
internal sealed class HttpTransport : IDisposable
{
    internal const string ApiKeyHeader = "X-API-Key";
    internal const string DelegationHeader = "X-Delegation-Token";

    private readonly Uri _baseUri;
    private readonly string? _apiKey;
    private readonly HttpClient _http;
    private readonly bool _ownsHttp;
    private readonly TimeSpan _timeout;
    private readonly int _maxRetries;
    private readonly TimeSpan _backoff;

    public HttpTransport(
        string baseUrl,
        string? apiKey,
        HttpClient? httpClient,
        TimeSpan timeout,
        int maxRetries,
        TimeSpan backoff)
    {
        if (string.IsNullOrWhiteSpace(baseUrl))
        {
            throw new ArgumentException("baseUrl is required", nameof(baseUrl));
        }
        _baseUri = new Uri(baseUrl.EndsWith('/') ? baseUrl : baseUrl + "/", UriKind.Absolute);
        _apiKey = string.IsNullOrEmpty(apiKey) ? null : apiKey;
        _ownsHttp = httpClient is null;
        // The per-attempt timeout below is ours; don't let HttpClient's default
        // 100s timeout interfere when we created the client.
        _http = httpClient ?? new HttpClient { Timeout = Timeout.InfiniteTimeSpan };
        _timeout = timeout;
        _maxRetries = Math.Max(0, maxRetries);
        _backoff = backoff;
    }

    /// <summary>Escape one path segment (ids, slugs).</summary>
    public static string Seg(string value) => Uri.EscapeDataString(value);

    public async Task<T> SendAsync<T>(
        HttpMethod method,
        string path,
        object? body,
        CancellationToken ct,
        string? delegationToken = null,
        bool retry = true)
    {
        using var doc = await SendRawAsync(method, path, body, ct, delegationToken, retry)
            .ConfigureAwait(false);
        if (doc is null)
        {
            return default!;
        }
        return doc.RootElement.Deserialize<T>(Json.Options)
            ?? throw new AuthzClientException($"empty response from {path}");
    }

    public async Task<JsonDocument?> SendRawAsync(
        HttpMethod method,
        string path,
        object? body,
        CancellationToken ct,
        string? delegationToken = null,
        bool retry = true)
    {
        var uri = new Uri(_baseUri, path.TrimStart('/'));
        var payload = body is null ? null : JsonSerializer.Serialize(body, body.GetType(), Json.Options);
        var maxRetries = retry ? _maxRetries : 0;
        Exception? lastError = null;

        for (var attempt = 0; attempt <= maxRetries; attempt++)
        {
            if (attempt > 0)
            {
                await Task.Delay(_backoff * Math.Pow(2, attempt - 1), ct).ConfigureAwait(false);
            }

            using var request = new HttpRequestMessage(method, uri);
            request.Headers.Accept.ParseAdd("application/json");
            if (_apiKey is not null)
            {
                request.Headers.TryAddWithoutValidation(ApiKeyHeader, _apiKey);
            }
            if (!string.IsNullOrEmpty(delegationToken))
            {
                request.Headers.TryAddWithoutValidation(DelegationHeader, delegationToken);
            }
            if (payload is not null)
            {
                request.Content = new StringContent(payload, Encoding.UTF8, "application/json");
            }

            using var attemptCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            if (_timeout > TimeSpan.Zero && _timeout != Timeout.InfiniteTimeSpan)
            {
                attemptCts.CancelAfter(_timeout);
            }

            HttpResponseMessage response;
            string text;
            try
            {
                response = await _http.SendAsync(request, attemptCts.Token).ConfigureAwait(false);
                text = await response.Content.ReadAsStringAsync(attemptCts.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                throw; // The caller cancelled: never retry that.
            }
            catch (Exception e) when (e is HttpRequestException or OperationCanceledException)
            {
                lastError = e; // Transport error or per-attempt timeout.
                continue;
            }

            using (response)
            {
                var status = (int)response.StatusCode;
                if (status >= 500 && attempt < maxRetries)
                {
                    // Transient server errors are retryable; client errors aren't.
                    continue;
                }
                if (status >= 400)
                {
                    throw new AuthzServiceException(status, text);
                }
                if (response.StatusCode == HttpStatusCode.NoContent || string.IsNullOrWhiteSpace(text))
                {
                    return null;
                }
                try
                {
                    return JsonDocument.Parse(text);
                }
                catch (JsonException e)
                {
                    throw new AuthzClientException($"invalid JSON from {path}", e);
                }
            }
        }
        throw new AuthzClientException(
            $"transport error after retries: {lastError?.Message}", lastError);
    }

    public void Dispose()
    {
        if (_ownsHttp)
        {
            _http.Dispose();
        }
    }
}

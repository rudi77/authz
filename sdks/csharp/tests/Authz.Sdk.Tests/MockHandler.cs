using System.Net;
using System.Text;

namespace Authz.Sdk.Tests;

/// <summary>A recorded request: method, path+query, headers we care about, body.</summary>
public sealed record Recorded(
    HttpMethod Method, string PathAndQuery, string? ApiKey, string? DelegationToken, string? Body);

/// <summary>
/// In-memory HttpMessageHandler: records every request and answers via the
/// handler, so tests assert on wire format, retries and caching.
/// </summary>
public sealed class MockHandler(Func<Recorded, (int Status, string Body)> respond) : HttpMessageHandler
{
    public List<Recorded> Requests { get; } = [];

    public int Calls => Requests.Count;

    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken ct)
    {
        string? Header(string name) =>
            request.Headers.TryGetValues(name, out var v) ? v.Single() : null;

        var body = request.Content is null ? null : await request.Content.ReadAsStringAsync(ct);
        var rec = new Recorded(
            request.Method, request.RequestUri!.PathAndQuery,
            Header("X-API-Key"), Header("X-Delegation-Token"), body);
        lock (Requests)
        {
            Requests.Add(rec);
        }
        var (status, text) = respond(rec);
        return new HttpResponseMessage((HttpStatusCode)status)
        {
            Content = new StringContent(text, Encoding.UTF8, "application/json"),
        };
    }

    public HttpClient Client() => new(this);
}

public sealed class FakeClock : TimeProvider
{
    public DateTimeOffset Now { get; set; } = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);

    public override DateTimeOffset GetUtcNow() => Now;
}

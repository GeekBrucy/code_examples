using System.Collections.Concurrent;

namespace client.Saml
{
    public sealed class AuthnRequestStore
    {
        private readonly ConcurrentDictionary<string, DateTime> _requests = new();

        public void Add(string requestId)
        {
            _requests[requestId] = DateTime.UtcNow;
        }

        public bool TryConsume(string requestId, TimeSpan maxAge)
        {
            if (_requests.TryRemove(requestId, out var issuedAt))
            {
                return DateTime.UtcNow - issuedAt <= maxAge;
            }

            return false;
        }
    }
}
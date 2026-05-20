using Microsoft.AspNetCore.Diagnostics;

namespace RPG_Login_API.Services
{
    public class UniversalExceptionHandler : IExceptionHandler
    {
        private readonly ILogger _logger;

        public UniversalExceptionHandler(ILogger<UniversalExceptionHandler> logger)
        {
            _logger = logger;
        }

        public ValueTask<bool> TryHandleAsync(HttpContext httpContext, Exception exception, CancellationToken cancellationToken)
        {
            //_logger.LogError(exception, "Unexpected exception: {Message}", exception.Message);

            httpContext.Response.StatusCode = 500;
            httpContext.Response.WriteAsJsonAsync("An unexpected error occurred during the request.", cancellationToken);

            return ValueTask.FromResult(true);
        }
    }
}

namespace RPG_Login_API.Utility
{
    public static class LogUtility
    {
        // IMPLEMENT CUSTOM LOGGING METHODS IN THIS CLASS, LIKE EASILY PARAMETERIZING
        //  THE LOG SEVERITY (INFO, WARNING, ERROR) AND THE SOURCE (CLASS NAME, METHOD NAME)

        private static Action<string?> _logMethod = Console.WriteLine;   // Default Console.WriteLine().

        public static void SetLogger(Action<string?> logMethod)
        {
            _logMethod = logMethod;
        }



        public static void LogMessage(string source, string message)
        {
            if (source == null || message == null) return;

            _logMethod.Invoke($"{DateTime.Now} [INFO] {source}: {message}");
        }

        public static void LogWarning(string source, string message)
        {
            if (source == null || message == null) return;

            Console.ForegroundColor = ConsoleColor.Yellow;
            _logMethod.Invoke($"{DateTime.Now} [WARN] {source}: {message}");
            Console.ForegroundColor = ConsoleColor.Gray;
        }

        public static void LogError(string source, string message)
        {
            if (source == null || message == null) return;

            Console.ForegroundColor = ConsoleColor.Red;
            _logMethod.Invoke($"{DateTime.Now} [ERROR] {source}: {message}");
            Console.ForegroundColor = ConsoleColor.Gray;
        }
    }
}

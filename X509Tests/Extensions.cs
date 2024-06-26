using FluentAssertions;
using Xunit.Sdk;

namespace X509Tests;

public static class Extensions
{
    public static T IsMatch<T>(this T expected)
    {
        return It.Is<T>(actual => actual.Matches(expected));
    }

    public static bool Matches<T>(this T actual, T expected)
    {
        try
        {
            actual.Should().BeEquivalentTo(expected);

            return true;
        }
        catch (XunitException)
        {
            return false;
        }
    }
}
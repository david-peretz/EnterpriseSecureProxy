namespace SecureProxy.Api.Domain;

/// <summary>Validation and placement rule for one caller supplied parameter of an <see cref="Operation"/>.</summary>
public sealed class ParameterRule
{
    public Guid Id { get; set; }

    public Guid OperationId { get; set; }
    public Operation Operation { get; set; } = null!;

    public string Name { get; set; } = string.Empty;

    public ParameterLocation Location { get; set; } = ParameterLocation.Query;

    public bool IsRequired { get; set; }

    public ParameterDataType DataType { get; set; } = ParameterDataType.String;

    /// <summary>Maximum string length (String/Guid/DateTime) or maximum raw JSON length for Object/Array.</summary>
    public int? MaxLength { get; set; }

    public decimal? MinValue { get; set; }
    public decimal? MaxValue { get; set; }

    /// <summary>Optional .NET regular expression a String value must match (evaluated with a match timeout).</summary>
    public string? Pattern { get; set; }

    /// <summary>Optional comma separated list of permitted values (String only).</summary>
    public string? AllowedValues { get; set; }
}

public enum ParameterLocation
{
    Path = 0,
    Query = 1,
    Body = 2
}

public enum ParameterDataType
{
    String = 0,
    Integer = 1,
    Number = 2,
    Boolean = 3,
    Guid = 4,
    DateTime = 5,
    Object = 6,
    Array = 7
}

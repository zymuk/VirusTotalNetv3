using System;
using VirusTotalNet.v3.Core;

namespace VirusTotalNet.v3.Models;

/// <summary>
/// Result-style discriminated union used by the non-throwing client surface
/// (<see cref="VirusTotalNet.v3.Core.IVtClient.TryGetAsync{T}"/> and the <c>Try*</c> Post overloads):
/// either the value (<see cref="IsSuccess"/>) or the API <see cref="Error"/>, never both.
/// </summary>
/// <typeparam name="T">Typed payload carried on success.</typeparam>
public sealed class VtResult<T>
{
    private VtResult(bool isSuccess, T? value, VtError? error)
    {
        IsSuccess = isSuccess;
        Value = value;
        Error = error;
    }

    /// <summary><c>true</c> when the request succeeded.</summary>
    public bool IsSuccess { get; }

    /// <summary>Typed payload on success; <c>default</c> on failure.</summary>
    public T? Value { get; }

    /// <summary>API error details on failure; <c>null</c> on success.</summary>
    public VtError? Error { get; }

    /// <summary>Creates a successful result.</summary>
    public static VtResult<T> Success(T? value) => new(isSuccess: true, value, null);

    /// <summary>Creates a failed result carrying the API error.</summary>
    public static VtResult<T> Failure(VtError error) => new(isSuccess: false, default, error ?? throw new ArgumentNullException(nameof(error)));

    /// <summary>Builds a result from an envelope: failure when it carries an <c>error</c>, success otherwise.</summary>
    public static VtResult<T> From(VtResponse<T> response)
    {
        if (response is null)
            throw new ArgumentNullException(nameof(response));
        return response.Error is null ? Success(response.Data) : Failure(response.Error);
    }

    /// <summary>Returns the value, or <c>default</c> on failure.</summary>
    public T? GetValueOrDefault() => Value;

    /// <summary>Returns the value, throwing a <see cref="VirusTotalException"/> when the request failed.</summary>
    public T ValueOrThrow() => IsSuccess
        ? Value!
        : throw new VtResultException(Error?.Message ?? "The request failed.", Error?.Code);
}
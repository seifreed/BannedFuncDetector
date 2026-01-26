#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
BannedFuncDetector - Result Type Pattern

This module implements a Result type pattern for better error handling,
inspired by Rust's Result<T, E> type. It provides a way to handle errors
without relying on exceptions for control flow.

Author: Marc Rivero | @seifreed
"""

from typing import Generic, TypeVar, Callable, NoReturn
from dataclasses import dataclass

T = TypeVar('T')
E = TypeVar('E')


@dataclass(frozen=True)
class Ok(Generic[T]):
    """
    Represents a successful result containing a value.

    Attributes:
        value: The success value of type T.

    Examples:
        >>> result = Ok(42)
        >>> result.is_ok()
        True
        >>> result.value
        42
        >>> result.unwrap()
        42
    """
    value: T

    def is_ok(self) -> bool:
        """Returns True, indicating this is a success result."""
        return True

    def is_err(self) -> bool:
        """Returns False, indicating this is not an error result."""
        return False

    def unwrap(self) -> T:
        """
        Returns the contained value.

        Returns:
            T: The success value.

        Examples:
            >>> Ok(42).unwrap()
            42
        """
        return self.value

    def unwrap_or(self, default: T) -> T:
        """
        Returns the contained value (ignores the default).

        Args:
            default: The default value (unused for Ok).

        Returns:
            T: The success value.

        Examples:
            >>> Ok(42).unwrap_or(0)
            42
        """
        return self.value

    def map(self, fn: 'Callable[[T], T]') -> 'Ok[T]':
        """
        Applies a function to the contained value.

        Args:
            fn: A function to apply to the value.

        Returns:
            Ok[T]: A new Ok with the transformed value.

        Examples:
            >>> Ok(2).map(lambda x: x * 2)
            Ok(value=4)
        """
        return Ok(fn(self.value))

    def map_err(self, fn: 'Callable[[E], E]') -> 'Ok[T]':
        """
        Returns self unchanged (no error to transform).

        Args:
            fn: A function (unused for Ok).

        Returns:
            Ok[T]: Self unchanged.
        """
        return self


@dataclass(frozen=True)
class Err(Generic[E]):
    """
    Represents a failed result containing an error.

    Attributes:
        error: The error value of type E.

    Examples:
        >>> result = Err("File not found")
        >>> result.is_err()
        True
        >>> result.error
        'File not found'
        >>> result.unwrap_or("default")
        'default'
    """
    error: E

    def is_ok(self) -> bool:
        """Returns False, indicating this is not a success result."""
        return False

    def is_err(self) -> bool:
        """Returns True, indicating this is an error result."""
        return True

    def unwrap(self) -> NoReturn:
        """
        Raises ValueError because this is an Err.

        Raises:
            ValueError: Always, with the error message.

        Examples:
            >>> Err("oops").unwrap()  # doctest: +IGNORE_EXCEPTION_DETAIL
            Traceback (most recent call last):
            ValueError: Called unwrap on Err: oops
        """
        raise ValueError(f"Called unwrap on Err: {self.error}")

    def unwrap_or(self, default: T) -> T:
        """
        Returns the default value because this is an Err.

        Args:
            default: The default value to return.

        Returns:
            T: The default value.

        Examples:
            >>> Err("oops").unwrap_or(42)
            42
        """
        return default

    def map(self, fn: 'Callable[[T], T]') -> 'Err[E]':
        """
        Returns self unchanged (no value to transform).

        Args:
            fn: A function (unused for Err).

        Returns:
            Err[E]: Self unchanged.
        """
        return self

    def map_err(self, fn: 'Callable[[E], E]') -> 'Err[E]':
        """
        Applies a function to the contained error.

        Args:
            fn: A function to apply to the error.

        Returns:
            Err[E]: A new Err with the transformed error.

        Examples:
            >>> Err("error").map_err(lambda e: e.upper())
            Err(error='ERROR')
        """
        return Err(fn(self.error))


Result = Ok[T] | Err[E]


def ok(value: T) -> Ok[T]:
    """
    Helper function to create an Ok result.

    Args:
        value: The success value.

    Returns:
        Ok[T]: An Ok result containing the value.

    Examples:
        >>> result = ok(42)
        >>> result.is_ok()
        True
    """
    return Ok(value)


def err(error: E) -> Err[E]:
    """
    Helper function to create an Err result.

    Args:
        error: The error value.

    Returns:
        Err[E]: An Err result containing the error.

    Examples:
        >>> result = err("Something went wrong")
        >>> result.is_err()
        True
    """
    return Err(error)


__all__ = [
    'Ok',
    'Err',
    'Result',
    'ok',
    'err',
]

/*
 * Copyright (c) 2016 Steven Soloff
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package io.github.ssoloff.secret;

import org.eclipse.jdt.annotation.Nullable;

/**
 * A checked exception that indicates an error occurred while working with a
 * {@link Secret}.
 *
 * <p>
 * This class is thread safe.
 * </p>
 */
public final class SecretException extends Exception {
    private static final long serialVersionUID = 6228526828438406187L;

    /**
     * Initializes a new instance of the {@code SecretException} class with no
     * detail message and no cause.
     */
    public SecretException() {
    }

    /**
     * Initializes a new instance of the {@code SecretException} class with the
     * specified detail message and no cause.
     *
     * @param message
     *            The detail message.
     */
    public SecretException(final @Nullable String message) {
        super(message);
    }

    /**
     * Initializes a new instance of the {@code SecretException} class with no
     * detail message and specified cause.
     *
     * @param cause
     *            The cause.
     */
    public SecretException(final @Nullable Throwable cause) {
        super(cause);
    }

    /**
     * Initializes a new instance of the {@code SecretException} class with the
     * specified detail message and cause.
     *
     * @param message
     *            The detail message.
     * @param cause
     *            The cause.
     */
    public SecretException(final @Nullable String message, final @Nullable Throwable cause) {
        super(message, cause);
    }
}

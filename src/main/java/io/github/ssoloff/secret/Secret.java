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

import java.util.Arrays;
import java.util.function.Consumer;

/**
 * A container for a value that must be kept secret and only disclosed for as
 * short of a time as possible.
 */
public final class Secret {
    private final byte[] ciphertext;

    private Secret(final byte[] ciphertext) {
        this.ciphertext = ciphertext;
    }

    /**
     * Creates a new instance of the {@code Secret} class from the specified
     * plaintext value.
     * 
     * <p>
     * The plaintext value is not modified by this method and should be scrubbed
     * by the caller as soon as possible if it is no longer needed.
     * </p>
     * 
     * @param plaintext
     *            The plaintext value to be kept secret.
     * 
     * @return A new instance of the {@code Secret} class.
     */
    public static Secret fromPlaintext(final byte[] plaintext) {
        final byte[] ciphertext = Arrays.copyOf(plaintext, plaintext.length);
        // TODO: encrypt
        return new Secret(ciphertext);
    }

    /**
     * Allows the specified consumer to perform an operation on the plaintext
     * secret value.
     * 
     * @param consumer
     *            The consumer to receive the plaintext secret value.
     */
    public void use(final Consumer<byte[]> consumer) {
        // TODO: decrypt
        final byte[] plaintext = Arrays.copyOf(ciphertext, ciphertext.length);
        try {
            consumer.accept(plaintext);
        } finally {
            Arrays.fill(plaintext, (byte) 0);
        }
    }
}

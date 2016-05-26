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
package io.github.ssoloff.secret

import io.github.ssoloff.secret.util.function.ThrowingConsumer
import io.github.ssoloff.secret.util.function.ThrowingFunction
import java.util.function.Consumer
import java.util.function.Function
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.NullCipher
import javax.crypto.SecretKey
import nl.jqno.equalsverifier.EqualsVerifier
import spock.lang.Specification
import spock.lang.Subject
import spock.lang.Title

abstract class AbstractSecretSpecification extends Specification {
    protected static final List<Byte> PLAINTEXT = [1, 2, 3, 4].asImmutable()

    private final def secrets = []

    protected def makeSecret(List<Byte> plaintext) {
        def secret = Secret.fromPlaintext(plaintext as byte[])
        secrets << secret
        secret
    }

    def cleanup() {
        secrets.forEach {
            try {
                it.close()
            } catch (final Exception e) {
                e.printStackTrace()
            }
        }
    }
}

@Subject(Secret)
@Title('Unit tests for Secret')
class SecretSpec extends AbstractSecretSpecification {
    private static final def RED_CIPHER_ALGORITHM = 'RC4'
    private static final def RED_CIPHER_KEY_SIZE_IN_BITS = 128

    private static def generateSecretKeyForRedOrBlackCipher() {
        def keyGenerator = KeyGenerator.getInstance(RED_CIPHER_ALGORITHM)
        keyGenerator.init(RED_CIPHER_KEY_SIZE_IN_BITS)
        keyGenerator.generateKey()
    }

    private static def getBlackCipher() {
        new NullCipher()
    }

    private static def getRedCipher() {
        Cipher.getInstance(RED_CIPHER_ALGORITHM)
    }

    def 'it should be equatable and hashable'() {
        expect: 'it should be equatable and hashable'
        EqualsVerifier.forClass(Secret.class)
                .withPrefabValues(Cipher.class, getRedCipher(), getBlackCipher())
                .withPrefabValues(SecretKey.class, generateSecretKeyForRedOrBlackCipher(), generateSecretKeyForRedOrBlackCipher())
                .verify()
    }

    def 'it should be equatable in terms of plaintext'() {
        given: 'a secret'
        def secret1 = makeSecret(PLAINTEXT)
        and: 'another secret with a different key and the same plaintext'
        def secret2 = makeSecret(PLAINTEXT)

        expect: 'they should be equal'
        secret1 == secret2
    }

    def 'it should be hashable in terms of plaintext'() {
        given: 'a secret'
        def secret1 = makeSecret(PLAINTEXT)
        and: 'another secret with a different key and the same plaintext'
        def secret2 = makeSecret(PLAINTEXT)

        expect: 'they should have the same hash code'
        secret1.hashCode() == secret2.hashCode()
    }
}

@Subject(Secret)
@Title('Unit tests for Secret#close')
class Secret_CloseSpec extends AbstractSecretSpecification {
    def 'when closed it should not throw an exception'() {
        given: 'a closed secret'
        def secret = makeSecret(PLAINTEXT)
        secret.close()

        when: 'the secret is closed again'
        secret.close()

        then: 'it should not throw an exception'
        noExceptionThrown()
    }
}

@Subject(Secret)
@Title('Unit tests for Secret#use')
class Secret_UseSpec extends AbstractSecretSpecification {
    def 'it should provide plaintext to consumer'() {
        given: 'a secret'
        def secret = makeSecret(PLAINTEXT)
        Consumer<byte[]> consumer = Mock()

        when: 'the secret is used'
        secret.use(consumer)

        then: 'the consumer should receive the plaintext'
        1 * consumer.accept(PLAINTEXT)
    }

    def 'it should scrub the plaintext after the consumer returns'() {
        given: 'a secret'
        def secret = makeSecret(PLAINTEXT)
        byte[] plaintext = []
        Consumer<byte[]> consumer = { plaintext = it }

        when: 'the secret is used'
        secret.use(consumer)

        then: 'the plaintext should be scrubbed after the consumer returns'
        plaintext == [0, 0, 0, 0]
    }

    def 'when closed it should throw an exception'() {
        given: 'a closed secret'
        def secret = makeSecret(PLAINTEXT)
        secret.close()
        Consumer<byte[]> consumer = Stub()

        when: 'the secret is used'
        secret.use(consumer)

        then: 'it should throw an exception'
        thrown(IllegalStateException)
    }
}

@Subject(Secret)
@Title('Unit tests for Secret#useAndReturn')
class Secret_UseAndReturnSpec extends AbstractSecretSpecification {
    def 'it should provide plaintext to function'() {
        given: 'a secret'
        def secret = makeSecret(PLAINTEXT)
        Function<byte[], Void> function = Mock()

        when: 'the secret is used'
        def actualResult = secret.useAndReturn(function)

        then: 'the function should receive the plaintext'
        1 * function.apply(PLAINTEXT)
    }

    def 'it should return function result'() {
        given: 'a secret'
        def secret = makeSecret(PLAINTEXT)
        String expectedResult = 'result'
        Function<byte[], String> function = Stub() {
            apply(_) >> expectedResult
        }

        when: 'the secret is used'
        def actualResult = secret.useAndReturn(function)

        then: 'it should return the function result'
        actualResult == expectedResult
    }

    def 'it should scrub the plaintext after the function returns'() {
        given: 'a secret'
        def secret = makeSecret(PLAINTEXT)
        byte[] plaintext = []
        Function<byte[], Void> function = { plaintext = it; null }

        when: 'the secret is used'
        secret.useAndReturn(function)

        then: 'the plaintext should be scrubbed after the function returns'
        plaintext == [0, 0, 0, 0]
    }

    def 'when closed it should throw an exception'() {
        given: 'a closed secret'
        def secret = makeSecret(PLAINTEXT)
        secret.close()
        Function<byte[], Void> function = Stub()

        when: 'the secret is used'
        secret.useAndReturn(function)

        then: 'it should throw an exception'
        thrown(IllegalStateException)
    }
}

@Subject(Secret)
@Title('Unit tests for Secret#useAndReturnOrThrow')
class Secret_UseAndReturnOrThrowSpec extends AbstractSecretSpecification {
    def 'it should provide plaintext to function'() {
        given: 'a secret'
        def secret = makeSecret(PLAINTEXT)
        ThrowingFunction<byte[], Void, Exception> function = Mock()

        when: 'the secret is used'
        def actualResult = secret.useAndReturnOrThrow(function)

        then: 'the function should receive the plaintext'
        1 * function.apply(PLAINTEXT)
    }

    def 'it should return function result'() {
        given: 'a secret'
        def secret = makeSecret(PLAINTEXT)
        String expectedResult = 'result'
        ThrowingFunction<byte[], String, Exception> function = Stub() {
            apply(_) >> expectedResult
        }

        when: 'the secret is used'
        def actualResult = secret.useAndReturnOrThrow(function)

        then: 'it should return the function result'
        actualResult == expectedResult
    }

    def 'when function throws an exception it should throw function exception'() {
        given: 'a secret'
        def secret = makeSecret(PLAINTEXT)
        and: 'a function that throws an exception'
        ThrowingFunction<byte[], String, IOException> function = Stub() {
            apply(_) >> {
                throw new IOException('the-message')
            }
        }

        when: 'the secret is used'
        secret.useAndReturnOrThrow(function)

        then: 'it should throw an exception'
        def e = thrown(IOException)
        e.message == 'the-message'
    }

    def 'it should scrub the plaintext after the function returns'() {
        given: 'a secret'
        def secret = makeSecret(PLAINTEXT)
        byte[] plaintext = []
        ThrowingFunction<byte[], Void, Exception> function = { plaintext = it; null }

        when: 'the secret is used'
        secret.useAndReturnOrThrow(function)

        then: 'the plaintext should be scrubbed after the function returns'
        plaintext == [0, 0, 0, 0]
    }

    def 'when closed it should throw an exception'() {
        given: 'a closed secret'
        def secret = makeSecret(PLAINTEXT)
        secret.close()
        ThrowingFunction<byte[], Void, Exception> function = Stub()

        when: 'the secret is used'
        secret.useAndReturnOrThrow(function)

        then: 'it should throw an exception'
        thrown(IllegalStateException)
    }
}

@Subject(Secret)
@Title('Unit tests for Secret#useOrThrow')
class Secret_UseOrThrowSpec extends AbstractSecretSpecification {
    def 'it should provide plaintext to consumer'() {
        given: 'a secret'
        def secret = makeSecret(PLAINTEXT)
        ThrowingConsumer<byte[], Exception> consumer = Mock()

        when: 'the secret is used'
        secret.useOrThrow(consumer)

        then: 'the consumer should receive the plaintext'
        1 * consumer.accept(PLAINTEXT)
    }

    def 'when consumer throws an exception it should throw consumer exception'() {
        given: 'a secret'
        def secret = makeSecret(PLAINTEXT)
        and: 'a consumer that throws an exception'
        ThrowingConsumer<byte[], IOException> consumer = Stub() {
            accept(_) >> {
                throw new IOException('the-message')
            }
        }

        when: 'the secret is used'
        secret.useOrThrow(consumer)

        then: 'it should throw an exception'
        def e = thrown(IOException)
        e.message == 'the-message'
    }

    def 'it should scrub the plaintext after the consumer returns'() {
        given: 'a secret'
        def secret = makeSecret(PLAINTEXT)
        byte[] plaintext = []
        ThrowingConsumer<byte[], Exception> consumer = { plaintext = it }

        when: 'the secret is used'
        secret.useOrThrow(consumer)

        then: 'the plaintext should be scrubbed after the consumer returns'
        plaintext == [0, 0, 0, 0]
    }

    def 'when closed it should throw an exception'() {
        given: 'a closed secret'
        def secret = makeSecret(PLAINTEXT)
        secret.close()
        ThrowingConsumer<byte[], Exception> consumer = Stub()

        when: 'the secret is used'
        secret.useOrThrow(consumer)

        then: 'it should throw an exception'
        thrown(IllegalStateException)
    }
}

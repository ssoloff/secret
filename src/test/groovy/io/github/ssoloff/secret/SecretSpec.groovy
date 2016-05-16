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

import java.util.function.Consumer
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.NullCipher
import javax.crypto.SecretKey
import nl.jqno.equalsverifier.EqualsVerifier
import nl.jqno.equalsverifier.Warning
import spock.lang.Specification
import spock.lang.Subject
import spock.lang.Title

@Subject(Secret)
@Title('Unit tests for Secret')
class SecretSpec extends Specification {
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
                .suppress(Warning.NULL_FIELDS)
                .verify()
    }

    def 'it should be equatable in terms of plaintext'() {
        given: 'a secret'
        def plaintext = [1, 2, 3, 4] as byte[]
        def secret1 = Secret.fromPlaintext(plaintext)
        and: 'another secret with a different key and the same plaintext'
        def secret2 = Secret.fromPlaintext(plaintext)

        expect: 'they should be equal'
        secret1 == secret2
    }

    def 'it should be hashable in terms of plaintext'() {
        given: 'a secret'
        def plaintext = [1, 2, 3, 4] as byte[]
        def secret1 = Secret.fromPlaintext(plaintext)
        and: 'another secret with a different key and the same plaintext'
        def secret2 = Secret.fromPlaintext(plaintext)

        expect: 'they should have the same hash code'
        secret1.hashCode() == secret2.hashCode()
    }
}

@Subject(Secret)
@Title('Unit tests for Secret#close')
class Secret_CloseSpec extends Specification {
    def 'when closed it should not throw an exception'() {
        given: 'a closed secret'
        def secret = Secret.fromPlaintext([1, 2, 3, 4] as byte[])
        secret.close()

        when: 'the secret is closed again'
        secret.close()

        then: 'it should not throw an exception'
        noExceptionThrown()
    }
}

@Subject(Secret)
@Title('Unit tests for Secret#use')
class Secret_UseSpec extends Specification {
    def 'it should provide plaintext to consumer'() {
        given: 'a secret'
        def plaintext = [1, 2, 3, 4] as byte[]
        def secret = Secret.fromPlaintext(plaintext)
        def consumer = Mock(Consumer)

        when: 'the secret is used'
        secret.use(consumer)

        then: 'the consumer should receive the plaintext'
        1 * consumer.accept(plaintext)
    }

    def 'it should scrub the plaintext after the consumer returns'() {
        given: 'a secret'
        def secret = Secret.fromPlaintext([1, 2, 3, 4] as byte[])
        def consumer = Mock(Consumer)

        when: 'the secret is used'
        secret.use(consumer)

        then: 'the plaintext should be scrubbed after the consumer returns'
        consumer.accept(_) >> { plaintext ->
            plaintext == [0, 0, 0, 0]
        }
    }

    def 'when closed it should throw an exception'() {
        given: 'a closed secret'
        def secret = Secret.fromPlaintext([1, 2, 3, 4] as byte[])
        secret.close()

        when: 'the secret is used'
        secret.use(Stub(Consumer))

        then: 'it should throw an exception'
        thrown(SecretException)
    }
}

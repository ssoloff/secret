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
import spock.lang.Specification
import spock.lang.Subject
import spock.lang.Title

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
}

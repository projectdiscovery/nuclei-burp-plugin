/*
 * MIT License
 *
 * Copyright (c) 2021 ProjectDiscovery, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 */

package io.projectdiscovery.nuclei.gui;

import org.fife.ui.rsyntaxtextarea.*;

import javax.swing.text.Segment;
import java.util.Collection;

public class NucleiTokenMaker extends AbstractTokenMaker {

    public static final String NUCLEI_YAML_SYNTAX = "text/yaml/nuclei";

    private int currentTokenStart;
    private int currentTokenType;

    public NucleiTokenMaker(Collection<String> preservedWords) {
        this.wordsToHighlight = new TokenMap();
        preservedWords.forEach(preservedWord -> this.wordsToHighlight.put(preservedWord, Token.RESERVED_WORD));
    }

    @Override
    public TokenMap getWordsToHighlight() {
        return this.wordsToHighlight;
    }

    @Override
    public void addToken(Segment segment, int start, int end, int tokenType, int startOffset) {
        if (tokenType == TokenTypes.IDENTIFIER) {
            final int value = this.wordsToHighlight.get(segment, start, end);
            if (value != -1) {
                tokenType = value;
            }
        }

        super.addToken(segment, start, end, tokenType, startOffset);
    }

    /**
     * Returns a list of tokens representing the given text.
     *
     * @param text           The text to break into tokens.
     * @param startTokenType The token with which to start tokenizing.
     * @param startOffset    The offset at which the line of tokens begins.
     * @return A linked list of tokens representing <code>text</code>.
     * @see <a href="https://github.com/bobbylight/RSyntaxTextArea/wiki/Adding-Syntax-Highlighting-for-a-new-Language">RSyntaxTextArea Documentation: Adding-Syntax-Highlighting-for-a-new-Language</a>
     */
    public Token getTokenList(Segment text, int startTokenType, int startOffset) {
        resetTokenList();

        final char[] array = text.array;
        final int offset = text.offset;
        final int count = text.count;
        final int end = offset + count;

        // Token starting offsets are always of the form:
        // 'startOffset + (currentTokenStart-offset)', but since startOffset and
        // offset are constant, tokens' starting positions become:
        // 'newStartOffset+currentTokenStart'.
        final int newStartOffset = startOffset - offset;

        this.currentTokenStart = offset;
        this.currentTokenType = startTokenType;

        for (int i = offset; i < end; i++) {
            final char c = array[i];

            switch (this.currentTokenType) {
                case Token.NULL:
                    nullToken(i, c);
                    break;
                case Token.WHITESPACE:
                    whiteSpace(text, newStartOffset, i, c);
                    break;
                case Token.IDENTIFIER:
                    identifier(text, newStartOffset, i, c);
                    break;
                case Token.LITERAL_NUMBER_DECIMAL_INT:
                    i = decimal(text, newStartOffset, i, c);
                    break;
                case Token.COMMENT_EOL:
                    i = commentEol(text, end, newStartOffset);
                    break;
                case Token.LITERAL_STRING_DOUBLE_QUOTE:
                    quotes(text, newStartOffset, i, c);
                    break;
                case TokenTypes.SEPARATOR:
                    switch (c) {
                        case ' ':
                        case '\t':
                            addToken(text, this.currentTokenStart, i - 1, TokenTypes.SEPARATOR, newStartOffset + this.currentTokenStart);
                            this.currentTokenStart = i;
                            this.currentTokenType = Token.WHITESPACE;
                            break;
                        case ':':
                            addToken(text, this.currentTokenStart, i - 1, TokenTypes.SEPARATOR, newStartOffset + this.currentTokenStart);
                            this.currentTokenStart = i;
                            this.currentTokenType = Token.SEPARATOR;
                            break;
                        case '\'':
                        case '"':
                            addToken(text, this.currentTokenStart, i - 1, TokenTypes.SEPARATOR, newStartOffset + this.currentTokenStart);
                            this.currentTokenStart = i;
                            this.currentTokenType = Token.LITERAL_STRING_DOUBLE_QUOTE;
                            break;
                        default:
                            if (RSyntaxUtilities.isLetterOrDigit(c) || c == '/' || c == '_') {
                                break;   // Still an identifier of some type.
                            }
                    }
                    break;
                default: // Should never happen
                    throw new IllegalStateException("this should never happen");
            }
        }

        switch (this.currentTokenType) {
            // Remember what token type to begin the next line with.
            case Token.LITERAL_STRING_DOUBLE_QUOTE:
                addToken(text, this.currentTokenStart, end - 1, this.currentTokenType, newStartOffset + this.currentTokenStart);
                break;
            // Do nothing if everything was okay.
            case Token.NULL:
                addNullToken();
                break;
            // All other token types don't continue to the next line...
            default:
                addToken(text, this.currentTokenStart, end - 1, this.currentTokenType, newStartOffset + this.currentTokenStart);
                addNullToken();
        }

        // Return the first token in our linked list.
        return this.firstToken;
    }

    private void quotes(Segment text, int newStartOffset, int i, char c) {
        if (c == '"' || c == '\'') {
            addToken(text, this.currentTokenStart, i, Token.LITERAL_STRING_DOUBLE_QUOTE, newStartOffset + this.currentTokenStart);
            this.currentTokenType = Token.NULL;
        }
    }

    private int commentEol(Segment text, int end, int newStartOffset) {
        final int i = end - 1;
        addToken(text, this.currentTokenStart, i, this.currentTokenType, newStartOffset + this.currentTokenStart);
        // We need to set token type to null so at the bottom we don't add one more token.
        this.currentTokenType = Token.NULL;
        return i;
    }

    private int decimal(Segment text, int newStartOffset, int i, char c) {
        switch (c) {
            case ' ':
            case '\t':
                addToken(text, this.currentTokenStart, i - 1, Token.LITERAL_NUMBER_DECIMAL_INT, newStartOffset + this.currentTokenStart);
                this.currentTokenStart = i;
                this.currentTokenType = Token.WHITESPACE;
                break;
            case '\'':
            case '"':
                addToken(text, this.currentTokenStart, i - 1, Token.LITERAL_NUMBER_DECIMAL_INT, newStartOffset + this.currentTokenStart);
                this.currentTokenStart = i;
                this.currentTokenType = Token.LITERAL_STRING_DOUBLE_QUOTE;
                break;
            default:
                if (RSyntaxUtilities.isDigit(c)) {
                    break;   // Still a literal number.
                }

                // Otherwise, remember this was a number and start over.
                addToken(text, this.currentTokenStart, i - 1, Token.LITERAL_NUMBER_DECIMAL_INT, newStartOffset + this.currentTokenStart);
                i--;
                this.currentTokenType = Token.NULL;
        }
        return i;
    }

    private void identifier(Segment text, int newStartOffset, int i, char c) {
        switch (c) {
            case ' ':
            case '\t':
                addToken(text, this.currentTokenStart, i - 1, Token.IDENTIFIER, newStartOffset + this.currentTokenStart);
                this.currentTokenStart = i;
                this.currentTokenType = Token.WHITESPACE;
                break;
            case ':':
                addToken(text, this.currentTokenStart, i - 1, Token.IDENTIFIER, newStartOffset + this.currentTokenStart);
                this.currentTokenStart = i;
                this.currentTokenType = Token.SEPARATOR;
                break;
            case '\'':
            case '"':
                addToken(text, this.currentTokenStart, i - 1, Token.IDENTIFIER, newStartOffset + this.currentTokenStart);
                this.currentTokenStart = i;
                this.currentTokenType = Token.LITERAL_STRING_DOUBLE_QUOTE;
                break;
            default:
                if (RSyntaxUtilities.isLetterOrDigit(c) || c == '/' || c == '_') {
                    break;   // Still an identifier of some type.
                }
        }
    }

    private void whiteSpace(Segment text, int newStartOffset, int i, char c) {
        switch (c) {
            case ' ':
            case '\t':
                break;   // Still whitespace.
            case '\'':
            case '"':
                addToken(text, this.currentTokenStart, i - 1, Token.WHITESPACE, newStartOffset + this.currentTokenStart);
                this.currentTokenStart = i;
                this.currentTokenType = Token.LITERAL_STRING_DOUBLE_QUOTE;
                break;
            case '#':
                addToken(text, this.currentTokenStart, i - 1, Token.WHITESPACE, newStartOffset + this.currentTokenStart);
                this.currentTokenStart = i;
                this.currentTokenType = Token.COMMENT_EOL;
                break;
            default:   // Add the whitespace token and start anew.
                addToken(text, this.currentTokenStart, i - 1, Token.WHITESPACE, newStartOffset + this.currentTokenStart);
                this.currentTokenStart = i;

                if (RSyntaxUtilities.isDigit(c)) {
                    this.currentTokenType = Token.LITERAL_NUMBER_DECIMAL_INT;
                    break;
                } else if (RSyntaxUtilities.isLetter(c) || c == '/' || c == '_') {
                    this.currentTokenType = Token.IDENTIFIER;
                    break;
                }
                // Anything not currently handled - mark as identifier
                this.currentTokenType = Token.IDENTIFIER;
        }
    }

    private void nullToken(int i, char c) {
        this.currentTokenStart = i;   // Starting a new token here.
        switch (c) {
            case ' ':
            case '\t':
                this.currentTokenType = Token.WHITESPACE;
                break;
            case '\'':
            case '"':
                this.currentTokenType = Token.LITERAL_STRING_DOUBLE_QUOTE;
                break;
            case '#':
                this.currentTokenType = Token.COMMENT_EOL;
                break;
            default:
                if (RSyntaxUtilities.isDigit(c)) {
                    this.currentTokenType = Token.LITERAL_NUMBER_DECIMAL_INT;
                    break;
                } else if (RSyntaxUtilities.isLetter(c) || c == '/' || c == '_') {
                    this.currentTokenType = Token.IDENTIFIER;
                    break;
                }
                // Anything not currently handled - mark as an identifier
                this.currentTokenType = Token.IDENTIFIER;
                break;
        }
    }
}

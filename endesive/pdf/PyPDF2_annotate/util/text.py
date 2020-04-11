# -*- coding: utf-8 -*-
"""
    Text Utils
    ~~~~~~~~~~

    :copyright: Copyright 2019 Autodesk, Inc.
    :license: MIT, see LICENSE for details.
"""


def unshift_token(text):
    """Remove a token from the front of a string.

    :param str text:
    :returns: {'text': str, 'separator': str, 'remainder': str}
    """
    if len(text) == 0:
        return {'text': text, 'separator': '', 'remainder': ''}

    token = ''
    for i in range(0, len(text)):
        char = text[i]
        if (char == ' ' and (len(token) >= 1 and token[i - 1] == ' ')):
            token += char
        elif (char == ' ' and len(token) == 0):
            token += char
        elif char == ' ':
            return {'text': token, 'separator': ' ', 'remainder': text[i + 1:]}
        elif char == '\n':
            return {
                'text': token,
                'separator': '\n',
                'remainder': text[i + 1:],
            }
        elif (len(token) >= 1 and token[i - 1] == ' '):
            return {
                'text': token,
                'separator': '',
                'remainder': text[len(token):],
            }
        else:
            token += char

    return {'text': token, 'separator': '', 'remainder': ''}


def unshift_line(text, measure, max_length):
    """Remove a line of text from a string.

    :param str text: text to be broken
    :param func measure: function that takes a string and returns its width
    :param int max_length: max width of each line
    :returns: {'text': str, 'remainder': str}
    """
    line = ''
    token = {'text': '', 'separator': '', 'remainder': text}
    while True:
        token = unshift_token(token['remainder'])
        token_text = token['text']
        remainder = token['remainder']
        separator = token['separator']
        if len(line) == 0:
            if len(token_text) > 0:
                # This allows us to add partial tokens for the first token
                for char in token_text:
                    if measure(line + char) > max_length:
                        line = char if len(line) == 0 else line
                        return {
                            'text': line,
                            'remainder': text[len(line):],
                        }
                    else:
                        line += char
                if separator == '\n':
                    return {'text': line, 'remainder': remainder}

                line += separator
            else:
                return {
                    'text': line,
                    'remainder': text[len(line) + len(separator):],
                }
        else:
            if measure(line + token_text) <= max_length:
                line += token_text
                if separator == '\n' or remainder == '':
                    return {'text': line, 'remainder': remainder}
                else:
                    line += separator
            else:
                return {'text': line, 'remainder': text[len(line):]}


def get_wrapped_lines(text, measure, max_length):
    """Break a string of text into lines wrapped to max_length.

    The algorithm is the same one used in the PGBS TextElement in web-viewer,
    to maintain consistency in line breaks.

    :param str text: text to be broken
    :param func measure: function that takes a string and returns its width
    :param int max_length: max width of each line
    :returns: list of strings
    """
    line = unshift_line(text, measure, max_length)
    lines = [line['text']]
    while (len(line['remainder']) > 0):
        line = unshift_line(line['remainder'], measure, max_length)
        lines.append(line['text'])
    return lines

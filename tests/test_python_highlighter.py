"""Preserve native text formats while avoiding a regex pass per keyword."""
from __future__ import annotations

from PySide6.QtCore import QRegularExpression
from PySide6.QtGui import QTextCursor, QTextDocument

from angerona.gui.sandbox_editor import PythonHighlighter


class _OriginalKeywordHighlighter(PythonHighlighter):
    """Reference the previous keyword passes; retain all other production rules."""

    def __init__(self, document):
        super().__init__(document)
        keyword_format = self._rules[0][1]
        self._rules[:1] = [(QRegularExpression(rf"\b{keyword}\b"), keyword_format)
                           for keyword in self._KEYWORDS]


def _formats(document):
    blocks = []
    block = document.begin()
    while block.isValid():
        blocks.append(tuple((span.start, span.length, span.format.foreground().color().name(),
                             span.format.fontWeight(), span.format.fontItalic())
                            for span in block.layout().formats()))
        block = block.next()
    return tuple(blocks)


_SOURCE = '\n'.join((
    ' '.join(PythonHighlighter._KEYWORDS),
    'async def classification(Falsehood, return_value):',
    '    await callback(12.5, None, True)  # return False and class Comment',
    'class ClassName(Base):',
    '    @decorator',
    '    def method(self):',
    '''        text = "class Return 123"; other = r'if None 52' ''',
    r'''        escaped = 'before\' return after'; quoted = "def\" with" ''',
    '        url = "# existing comment precedence remains unchanged"',
    '        pass  # "quoted" def name 123',
    'emoji_😀 = "🛡 False"; nonlocal_name = None; TrueSuffix = False',
    'without = NoneValue; classify = keywordish; async_await = 10',
))


def test_combined_keywords_preserve_every_native_format_and_edit():
    documents = [QTextDocument(_SOURCE), QTextDocument(_SOURCE)]
    highlighters = [_OriginalKeywordHighlighter(documents[0]), PythonHighlighter(documents[1])]
    for highlighter in highlighters:
        highlighter.rehighlight()
    assert _formats(documents[0]) == _formats(documents[1])
    assert all(document.toPlainText() == _SOURCE for document in documents)

    # The editor keeps the complete text and remains editable; edits still get
    # the same keyword/name/string/comment override semantics as the reference.
    inserted = '\n@added\nasync def additional():\n    return "class 7"  # None\n'
    for document, highlighter in zip(documents, highlighters):
        cursor = QTextCursor(document)
        cursor.movePosition(QTextCursor.MoveOperation.End)
        cursor.insertText(inserted)
        highlighter.rehighlight()
        assert document.toPlainText() == _SOURCE + inserted
    assert _formats(documents[0]) == _formats(documents[1])


def test_large_document_uses_at_least_five_times_fewer_regex_searches():
    source = '\n'.join([_SOURCE] * 50)
    documents = [QTextDocument(source), QTextDocument(source)]
    highlighters = [_OriginalKeywordHighlighter(documents[0]), PythonHighlighter(documents[1])]
    calls = [0, 0]

    class CountedExpression:
        def __init__(self, expression, index):
            self.expression, self.index = expression, index

        def globalMatch(self, text):  # noqa: N802 - QRegularExpression API
            calls[self.index] += 1
            return self.expression.globalMatch(text)

    for index, highlighter in enumerate(highlighters):
        highlighter._rules = [(CountedExpression(expression, index), style)
                              for expression, style in highlighter._rules]
        highlighter.rehighlight()
    assert calls[1] > 0 and calls[0] >= 5 * calls[1]
    assert _formats(documents[0]) == _formats(documents[1])
    assert all(document.toPlainText() == source for document in documents)

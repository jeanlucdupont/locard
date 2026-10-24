#!/usr/bin/python
#    This file is part of python-evtx.
#
#   Copyright 2012, 2013 Willi Ballenthin <william.ballenthin@mandiant.com>
#                    while at Mandiant <http://www.mandiant.com>
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
"""Minimal python-evtx 0.8.1 extension; no site-packages or global mutation.

The renderer/substitution traversal is adapted from upstream Views.py/Nodes.py
(Apache-2.0). Locard additions decode six numeric arrays and repeat their
containing element, as validated against Windows. Other variants delegate to
upstream unchanged. Unknown array shapes fail closed.
"""
import struct

import Evtx.Nodes as e_nodes
from Evtx.BinaryParser import ParseException
from Evtx.Evtx import Record as UpstreamRecord
from Evtx.Views import escape_value, validate_name, UnexpectedElementException

ARRAY_TYPES = {0x84: (1, "B", False), 0x86: (2, "H", False), 0x88: (4, "I", False),
               0x8A: (8, "Q", False), 0x94: (4, "I", True),
               0x95: (8, "Q", True)}


class ScalarText:
    def __init__(self, value):
        self.value = value

    def string(self):
        return self.value


class NumericArray:
    def __init__(self, buf, offset, length, type_, lower, upper):
        width, code, hexadecimal = ARRAY_TYPES[type_]
        if (not isinstance(length, int) or length < 0 or length % width
                or offset < lower or offset + length > min(upper, len(buf))):
            raise ParseException("Numeric array exceeds bounds or has invalid length")
        self.size = length
        self.values = tuple((hex(value) if hexadecimal else str(value))
                            for (value,) in struct.iter_unpack(
                                "<" + code, buf[offset:offset + length]))

    def length(self):
        return self.size

    def string(self):
        raise ParseException("Numeric array requires element expansion")


def array_bounds(root):
    chunk = root._chunk
    lower, upper = chunk.offset() + 512, chunk.offset() + chunk.next_record_offset()
    parent = root
    while parent is not None:
        if isinstance(parent, UpstreamRecord):
            lower = max(lower, parent.offset() + 24)
            upper = min(upper, parent.offset() + parent.length() - 4)
        elif isinstance(parent, e_nodes.BXmlTypeNode) and parent._length is not None:
            lower = max(lower, parent.offset())
            upper = min(upper, parent.offset() + parent._length)
        parent = getattr(parent, "_parent", None)
    return lower, upper


def substitutions(root):
    # Mirrors RootNode.substitutions; only the six supported arrays take a new path.
    ofs = root.tag_and_children_length()
    count = root.unpack_dword(ofs)
    ofs += 4
    declarations = []
    for _ in range(count):
        declarations.append((root.unpack_word(ofs), root.unpack_byte(ofs + 2)))
        ofs += 4
    result = []
    for size, type_ in declarations:
        offset = root.offset() + ofs
        if type_ in ARRAY_TYPES:
            value = NumericArray(root._buf, offset, size, type_, *array_bounds(root))
        else:
            value = e_nodes.get_variant_value(root._buf, offset, root._chunk,
                                             root, type_, length=size)
            if abs(size - value.length()) > 4:
                raise ParseException("Invalid substitution value size")
        result.append(value)
        ofs += size
    return result


class Record(UpstreamRecord):
    def xml(self):
        return render_root_node(self.root())


def render_root_node_with_subs(root_node, subs):
    """
    render the given root node using the given substitutions into XML.

    Args:
      root_node (e_nodes.RootNode): the node to render.
      subs (list[str]): the substitutions that maybe included in the XML.

    Returns:
      str: the rendered XML document.
    """

    def rec(node, acc, current_subs):
        if isinstance(node, e_nodes.EndOfStreamNode):
            pass  # intended
        elif isinstance(node, e_nodes.OpenStartElementNode):
            arrays = [child for child in node.children()
                      if isinstance(child, (e_nodes.NormalSubstitutionNode,
                                            e_nodes.ConditionalSubstitutionNode))
                      and isinstance(current_subs[child.index()], NumericArray)]
            if arrays:
                # Only the Windows-validated sole-content substitution shape.
                content = [child for child in node.children()
                           if not isinstance(child, (e_nodes.AttributeNode,
                               e_nodes.CloseStartElementNode, e_nodes.CloseElementNode,
                               e_nodes.CloseEmptyElementNode))]
                if len(arrays) != 1 or content != arrays:
                    raise ParseException("Unsupported numeric-array element structure")
                index = arrays[0].index()
                # Windows retains one empty element for a zero-length array.
                for value in current_subs[index].values or ("",):
                    replacement = list(current_subs)
                    replacement[index] = ScalarText(value)
                    rec(node, acc, replacement)
                return
            acc.append("<")
            acc.append(node.tag_name())
            for child in node.children():
                if isinstance(child, e_nodes.AttributeNode):
                    acc.append(" ")
                    acc.append(validate_name(child.attribute_name().string()))
                    acc.append('="')
                    # TODO: should use xml.sax.saxutils.quoteattr here
                    # but to do so, we'd need to ensure we're not double-quoting this value.
                    rec(child.attribute_value(), acc, current_subs)
                    acc.append('"')
            acc.append(">")
            for child in node.children():
                rec(child, acc, current_subs)
            acc.append("</")
            acc.append(validate_name(node.tag_name()))
            acc.append(">\n")
        elif isinstance(node, e_nodes.CloseStartElementNode):
            pass  # intended
        elif isinstance(node, e_nodes.CloseEmptyElementNode):
            pass  # intended
        elif isinstance(node, e_nodes.CloseElementNode):
            pass  # intended
        elif isinstance(node, e_nodes.ValueNode):
            acc.append(escape_value(node.children()[0].string()))
        elif isinstance(node, e_nodes.AttributeNode):
            pass  # intended
        elif isinstance(node, e_nodes.CDataSectionNode):
            acc.append("<![CDATA[")
            # TODO: is this correct escaping???
            acc.append(escape_value(node.cdata()))
            acc.append("]]>")
        elif isinstance(node, e_nodes.EntityReferenceNode):
            acc.append(escape_value(node.entity_reference()))
        elif isinstance(node, e_nodes.ProcessingInstructionTargetNode):
            acc.append(escape_value(node.processing_instruction_target()))
        elif isinstance(node, e_nodes.ProcessingInstructionDataNode):
            acc.append(escape_value(node.string()))
        elif isinstance(node, e_nodes.TemplateInstanceNode):
            raise UnexpectedElementException("TemplateInstanceNode")
        elif isinstance(node, e_nodes.NormalSubstitutionNode):
            sub = current_subs[node.index()]

            if isinstance(sub, e_nodes.BXmlTypeNode):
                sub = render_root_node(sub.root())
            else:
                sub = escape_value(sub.string())

            acc.append(sub)
        elif isinstance(node, e_nodes.ConditionalSubstitutionNode):
            sub = current_subs[node.index()]

            if isinstance(sub, e_nodes.BXmlTypeNode):
                sub = render_root_node(sub.root())
            else:
                sub = escape_value(sub.string())

            acc.append(sub)
        elif isinstance(node, e_nodes.StreamStartNode):
            pass  # intended

    acc = []
    for c in root_node.template().children():
        rec(c, acc, subs)
    return "".join(acc)


def render_root_node(root_node):
    subs = []
    for sub in substitutions(root_node):
        if isinstance(sub, str):
            raise RuntimeError("string sub?")

        if sub is None:
            raise RuntimeError("null sub?")

        subs.append(sub)

    return render_root_node_with_subs(root_node, subs)



from typing import TypeAlias

from .base import DeprecatedNode, NodeType
from .call_site import CallSiteNode
from .code import ClassNode, CodeBlockNode, CodeBlockType, FunctionNode
from .finding import FindingNode, FindingSeverity, FindingTool
from .module_node import ModuleNode
from .taint import (
    SanitizerEffectiveness,
    SanitizerNode,
    SanitizerType,
    SeverityLevel,
    TaintSinkNode,
    TaintSinkType,
    TaintSourceNode,
    TaintSourceType,
)
from .variable import VariableNode, VariableScope

Node: TypeAlias = FunctionNode | ClassNode | CodeBlockNode | ModuleNode | VariableNode

__all__ = [
    "DeprecatedNode",
    "NodeType",
    "CallSiteNode",
    "ClassNode",
    "CodeBlockNode",
    "CodeBlockType",
    "FunctionNode",
    "FindingNode",
    "FindingSeverity",
    "FindingTool",
    "ModuleNode",
    "SanitizerEffectiveness",
    "SanitizerNode",
    "SanitizerType",
    "SeverityLevel",
    "TaintSinkNode",
    "TaintSinkType",
    "TaintSourceNode",
    "TaintSourceType",
    "VariableNode",
    "VariableScope",
    "Node",
]

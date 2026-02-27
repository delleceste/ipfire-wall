#!/usr/bin/env python3

import os
import sys
from pygments import highlight, lex
from pygments.lexers import get_lexer_by_name
from pygments.formatters import HtmlFormatter
from pygments.token import Token

# Logical order mimicking the packet flow and logical layers
FILES = [
    "module_init.h",
    "module_init.c",
    "ipfire.h",
    "ipfire.c",
    "ipfi_macros.h",
    "ipfi_entry.h",
    "table_lifecycle.c",
    "filter/filter_engine.h",
    "filter/filter_engine.c",
    "filter/rule_match.h",
    "filter/rule_match.c",
    "filter/header_check.h",
    "filter/header_check.c",
    "filter/defrag.h",
    "filter/defrag.c",
    "nat/nat.h",
    "nat/nat_engine.c",
    "nat/nat_table.h",
    "nat/nat_table.c",
    "nat/translation.h",
    "mangle/mangle.h",
    "mangle/mangle.c",
    "mangle/tcpmss.h",
    "mangle/tcpmss.c",
    "logging/log.h",
    "logging/log.c",
    "helpers/ftp.h",
    "helpers/ftp.c",
    "helpers/icmp_nat.h",
    "helpers/icmp_nat.c",
    "netlink/message_builder.h",
    "netlink/message_builder.c",
    "netlink/netlink_data.c",
    "netlink/rule_sync.c",
    "netlink/netlink_control.c",
    "netlink/netlink.c",
    "netlink/ipfi_netl.h",
    "proc/proc.h",
    "proc/proc.c",
    "common/globals.c",
    "common/stats.c",
    "globals.h",
    "offset.c"
]

# Custom CSS for high-fidelity semantic highlighting
CUSTOM_CSS = """
/* General Source Styling */
.source-code { 
    background: #ffffff; 
    border: 1px solid #e1e4e8;
    border-radius: 6px; 
    padding: 16px; 
    font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, monospace;
    font-size: 10px;
    line-height: 1.45;
    color: #24292e;
}

/* Base Highlighting (inspired by GitHub/VSCode) */
.source-code .k  { color: #d73a49; font-weight: bold; }       /* Keywords: struct, if, return (Red) */
.source-code .kt { color: #005cc5; font-weight: bold; }       /* Built-in Types: int, char (Blue) */
.source-code .kn { color: #d73a49; font-weight: bold; }       /* Keywords.Namespace: #include */
.source-code .nc { color: #2b91af !important; font-weight: bold; } /* Custom Types / Struct Names (Teal) */
.source-code .nf { color: #6f42c1; font-weight: bold; }       /* Name.Function Definitions (Purple) */
.source-code .no { color: #005cc5; font-weight: bold; }       /* Name.Constant (Blue) */
.source-code .o  { color: #d73a49; font-weight: bold; }       /* Operators: =, +, -> (Red) */
.source-code .p  { color: #24292e; }                          /* Punctuation: ( ) { } ; */
.source-code .m  { color: #005cc5; }                          /* Numbers */
.source-code .s  { color: #032f62; }                          /* Strings */
.source-code .cm, .source-code .c1 { color: #6a737d; font-style: italic; } /* Comments */

/* Semantic Overrides (Variable Scopes) */
.source-code span.v-global    { color: #b010b0 !important; font-weight: bold; } /* Magenta for Globals */
.source-code span.v-param     { color: #22863a !important; font-weight: bold; } /* Green for Parameters */
.source-code span.v-local     { color: #e36209 !important; }                     /* Orange for Locals/Variables */
.source-code span.v-func-call { color: #003366 !important; font-weight: bold; } /* Dark Blue for Function Calls */
.source-code span.v-member    { color: #213547 !important; font-weight: bold; font-style: italic; } /* Dark Slate for Members */

/* Specifically targeting switch/case labels */
.source-code .nl { color: #005cc5; font-weight: bold; }       /* Name.Label: case labels */
"""

class SemanticCFormatter:
    def __init__(self):
        self.lexer = get_lexer_by_name('c', stripall=True)
        self.base_formatter = HtmlFormatter()
        
    def analyze_and_render(self, code):
        tokens = list(lex(code, self.lexer))
        
        scope_depth = 0
        in_function_params = False
        current_func_params = set()
        processed_tokens = []
        
        for i, (ttype, value) in enumerate(tokens):
            css_class = ""
            
            # Heuristic for scope tracking
            if value == '{': 
                scope_depth += 1
            elif value == '}': 
                scope_depth = max(0, scope_depth - 1)
                if scope_depth == 0:
                    current_func_params.clear()
            
            # Heuristic for parameter tracking
            if value == '(':
                prev_idx = i - 1
                while prev_idx >= 0 and tokens[prev_idx][0] in Token.Text:
                    prev_idx -= 1
                if prev_idx >= 0 and (tokens[prev_idx][0] in (Token.Name, Token.Name.Function) or value == '('):
                    if scope_depth == 0:
                        in_function_params = True
            elif value == ')':
                in_function_params = False

            # Semantic Tagging
            if ttype in Token.Name or ttype == Token.Name:
                name_str = value.strip()
                
                # A. Detect Function Call
                next_idx = i + 1
                while next_idx < len(tokens) and tokens[next_idx][0] in Token.Text:
                    next_idx += 1
                is_func_call = next_idx < len(tokens) and tokens[next_idx][1] == '('
                
                # B. Detect Member access (handling split -> or .)
                is_member = False
                prev_idx = i - 1
                while prev_idx >= 0 and tokens[prev_idx][0] in Token.Text:
                    prev_idx -= 1
                if prev_idx >= 0:
                    if tokens[prev_idx][1] in ('.', '->'):
                        is_member = True
                    elif tokens[prev_idx][1] == '>': # Check for split '-' '>'
                        pp_idx = prev_idx - 1
                        while pp_idx >= 0 and tokens[pp_idx][0] in Token.Text: pp_idx -= 1
                        if pp_idx >= 0 and tokens[pp_idx][1] == '-':
                            is_member = True

                # C. Detect Custom Type Type (nc)
                is_custom_type = False
                # 1. Preceded by 'struct'
                if prev_idx >= 0 and tokens[prev_idx][1] == 'struct':
                    is_custom_type = True
                # 2. Lookahead: Type followed by * or variable name
                if not is_custom_type and not is_func_call and not is_member:
                    n1 = next_idx # next_idx is already pointing past whitespace
                    if n1 < len(tokens):
                        if tokens[n1][1] == '*' or tokens[n1][0] in Token.Name:
                            # It's likely a type name in a declaration
                            is_custom_type = True

                # Apply logic based on priority
                if is_custom_type:
                    css_class = "nc"
                elif is_func_call and scope_depth > 0:
                    css_class = "v-func-call"
                elif is_member:
                    css_class = "v-member"
                elif in_function_params:
                    css_class = "v-param"
                    if name_str and len(name_str) > 1:
                        current_func_params.add(name_str)
                elif name_str in current_func_params:
                    css_class = "v-param"
                elif scope_depth == 0:
                    css_class = "v-global"
                else:
                    css_class = "v-local"

            # Escape HTML
            val_escaped = value.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;')
            
            # Get default classes
            pyg_classes = self.base_formatter._get_css_classes(ttype)
            full_class = pyg_classes
            if css_class:
                full_class = f"{full_class} {css_class}".strip()
                
            if full_class:
                processed_tokens.append(f'<span class="{full_class}">{val_escaped}</span>')
            else:
                processed_tokens.append(val_escaped)
                
        return f'<pre class="source-code">{"".join(processed_tokens)}</pre>'

def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    kernel_dir = os.path.abspath(os.path.join(script_dir, "../../kernel"))
    output_file = os.path.abspath(os.path.join(script_dir, "../99_Appendix_Source_Code.md"))
    
    analyzer = SemanticCFormatter()

    with open(output_file, 'w') as outf:
        outf.write("# Appendix: Source Code\n\n")
        outf.write("This appendix contains all the kernel module source code logically ordered.\n\n")
        outf.write(f"<style>\n{CUSTOM_CSS}\n</style>\n\n")

        for file in FILES:
            path = os.path.join(kernel_dir, file)
            if not os.path.exists(path):
                continue
                
            outf.write(f"## {file}\n\n")
            with open(path, 'r') as inf:
                code_content = inf.read()
            html_content = analyzer.analyze_and_render(code_content)
            outf.write(html_content)
            outf.write("\n\n")

if __name__ == "__main__":
    main()

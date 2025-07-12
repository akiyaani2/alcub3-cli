import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
import { Text, Box } from 'ink';
import { Colors } from '../../colors.js';
export const UserMessage = ({ text }) => {
    const prefix = '> ';
    const prefixWidth = prefix.length;
    return (_jsxs(Box, { borderStyle: "round", borderColor: Colors.Gray, flexDirection: "row", paddingX: 2, paddingY: 0, marginY: 1, alignSelf: "flex-start", children: [_jsx(Box, { width: prefixWidth, children: _jsx(Text, { color: Colors.Gray, children: prefix }) }), _jsx(Box, { flexGrow: 1, children: _jsx(Text, { wrap: "wrap", color: Colors.Gray, children: text }) })] }));
};
//# sourceMappingURL=UserMessage.js.map
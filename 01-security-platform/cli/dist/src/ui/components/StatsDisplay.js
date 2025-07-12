import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
import { Box, Text } from 'ink';
import Gradient from 'ink-gradient';
import { Colors } from '../colors.js';
import { formatDuration } from '../utils/formatters.js';
import { useSessionStats } from '../contexts/SessionContext.js';
import { getStatusColor, TOOL_SUCCESS_RATE_HIGH, TOOL_SUCCESS_RATE_MEDIUM, USER_AGREEMENT_RATE_HIGH, USER_AGREEMENT_RATE_MEDIUM, } from '../utils/displayUtils.js';
import { computeSessionStats } from '../utils/computeStats.js';
const StatRow = ({ title, children }) => (_jsxs(Box, { children: [_jsx(Box, { width: 28, children: _jsx(Text, { color: Colors.LightBlue, children: title }) }), children] }));
const SubStatRow = ({ title, children }) => (_jsxs(Box, { paddingLeft: 2, children: [_jsx(Box, { width: 26, children: _jsxs(Text, { children: ["\u00BB ", title] }) }), children] }));
const Section = ({ title, children }) => (_jsxs(Box, { flexDirection: "column", width: "100%", marginBottom: 1, children: [_jsx(Text, { bold: true, children: title }), children] }));
const ModelUsageTable = ({ models, totalCachedTokens, cacheEfficiency }) => {
    const nameWidth = 25;
    const requestsWidth = 8;
    const inputTokensWidth = 15;
    const outputTokensWidth = 15;
    return (_jsxs(Box, { flexDirection: "column", marginTop: 1, children: [_jsxs(Box, { children: [_jsx(Box, { width: nameWidth, children: _jsx(Text, { bold: true, children: "Model Usage" }) }), _jsx(Box, { width: requestsWidth, justifyContent: "flex-end", children: _jsx(Text, { bold: true, children: "Reqs" }) }), _jsx(Box, { width: inputTokensWidth, justifyContent: "flex-end", children: _jsx(Text, { bold: true, children: "Input Tokens" }) }), _jsx(Box, { width: outputTokensWidth, justifyContent: "flex-end", children: _jsx(Text, { bold: true, children: "Output Tokens" }) })] }), _jsx(Box, { borderStyle: "round", borderBottom: true, borderTop: false, borderLeft: false, borderRight: false, width: nameWidth + requestsWidth + inputTokensWidth + outputTokensWidth }), Object.entries(models).map(([name, modelMetrics]) => (_jsxs(Box, { children: [_jsx(Box, { width: nameWidth, children: _jsx(Text, { children: name.replace('-001', '') }) }), _jsx(Box, { width: requestsWidth, justifyContent: "flex-end", children: _jsx(Text, { children: modelMetrics.api.totalRequests }) }), _jsx(Box, { width: inputTokensWidth, justifyContent: "flex-end", children: _jsx(Text, { color: Colors.AccentYellow, children: modelMetrics.tokens.prompt.toLocaleString() }) }), _jsx(Box, { width: outputTokensWidth, justifyContent: "flex-end", children: _jsx(Text, { color: Colors.AccentYellow, children: modelMetrics.tokens.candidates.toLocaleString() }) })] }, name))), cacheEfficiency > 0 && (_jsxs(Box, { flexDirection: "column", marginTop: 1, children: [_jsxs(Text, { children: [_jsx(Text, { color: Colors.AccentGreen, children: "Savings Highlight:" }), ' ', totalCachedTokens.toLocaleString(), " (", cacheEfficiency.toFixed(1), "%) of input tokens were served from the cache, reducing costs."] }), _jsx(Box, { height: 1 }), _jsx(Text, { color: Colors.Gray, children: "\u00BB Tip: For a full token breakdown, run `/stats model`." })] }))] }));
};
export const StatsDisplay = ({ duration, title, }) => {
    const { stats } = useSessionStats();
    const { metrics } = stats;
    const { models, tools } = metrics;
    const computed = computeSessionStats(metrics);
    const successThresholds = {
        green: TOOL_SUCCESS_RATE_HIGH,
        yellow: TOOL_SUCCESS_RATE_MEDIUM,
    };
    const agreementThresholds = {
        green: USER_AGREEMENT_RATE_HIGH,
        yellow: USER_AGREEMENT_RATE_MEDIUM,
    };
    const successColor = getStatusColor(computed.successRate, successThresholds);
    const agreementColor = getStatusColor(computed.agreementRate, agreementThresholds);
    const renderTitle = () => {
        if (title) {
            return Colors.GradientColors && Colors.GradientColors.length > 0 ? (_jsx(Gradient, { colors: Colors.GradientColors, children: _jsx(Text, { bold: true, children: title }) })) : (_jsx(Text, { bold: true, color: Colors.AccentPurple, children: title }));
        }
        return (_jsx(Text, { bold: true, color: Colors.AccentPurple, children: "Session Stats" }));
    };
    return (_jsxs(Box, { borderStyle: "round", borderColor: Colors.Gray, flexDirection: "column", paddingY: 1, paddingX: 2, children: [renderTitle(), _jsx(Box, { height: 1 }), tools.totalCalls > 0 && (_jsxs(Section, { title: "Interaction Summary", children: [_jsx(StatRow, { title: "Tool Calls:", children: _jsxs(Text, { children: [tools.totalCalls, " (", ' ', _jsxs(Text, { color: Colors.AccentGreen, children: ["\u2714 ", tools.totalSuccess] }), ' ', _jsxs(Text, { color: Colors.AccentRed, children: ["\u2716 ", tools.totalFail] }), " )"] }) }), _jsx(StatRow, { title: "Success Rate:", children: _jsxs(Text, { color: successColor, children: [computed.successRate.toFixed(1), "%"] }) }), computed.totalDecisions > 0 && (_jsx(StatRow, { title: "User Agreement:", children: _jsxs(Text, { color: agreementColor, children: [computed.agreementRate.toFixed(1), "%", ' ', _jsxs(Text, { color: Colors.Gray, children: ["(", computed.totalDecisions, " reviewed)"] })] }) }))] })), _jsxs(Section, { title: "Performance", children: [_jsx(StatRow, { title: "Wall Time:", children: _jsx(Text, { children: duration }) }), _jsx(StatRow, { title: "Agent Active:", children: _jsx(Text, { children: formatDuration(computed.agentActiveTime) }) }), _jsx(SubStatRow, { title: "API Time:", children: _jsxs(Text, { children: [formatDuration(computed.totalApiTime), ' ', _jsxs(Text, { color: Colors.Gray, children: ["(", computed.apiTimePercent.toFixed(1), "%)"] })] }) }), _jsx(SubStatRow, { title: "Tool Time:", children: _jsxs(Text, { children: [formatDuration(computed.totalToolTime), ' ', _jsxs(Text, { color: Colors.Gray, children: ["(", computed.toolTimePercent.toFixed(1), "%)"] })] }) })] }), Object.keys(models).length > 0 && (_jsx(ModelUsageTable, { models: models, totalCachedTokens: computed.totalCachedTokens, cacheEfficiency: computed.cacheEfficiency }))] }));
};
//# sourceMappingURL=StatsDisplay.js.map
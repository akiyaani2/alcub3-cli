import { jsx as _jsx } from "react/jsx-runtime";
import { Text } from 'ink';
import Spinner from 'ink-spinner';
import { useStreamingContext } from '../contexts/StreamingContext.js';
import { StreamingState } from '../types.js';
export const GeminiRespondingSpinner = ({ nonRespondingDisplay, spinnerType = 'dots' }) => {
    const streamingState = useStreamingContext();
    if (streamingState === StreamingState.Responding) {
        return _jsx(Spinner, { type: spinnerType });
    }
    else if (nonRespondingDisplay) {
        return _jsx(Text, { children: nonRespondingDisplay });
    }
    return null;
};
//# sourceMappingURL=GeminiRespondingSpinner.js.map
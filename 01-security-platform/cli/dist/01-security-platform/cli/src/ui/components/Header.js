import { jsx as _jsx } from "react/jsx-runtime";
import { Box, Text } from 'ink';
import Gradient from 'ink-gradient';
import { Colors } from '../colors.js';
import { shortAsciiLogo, longAsciiLogo } from './AsciiArt.js';
import { getAsciiArtWidth } from '../utils/textUtils.js';
export const Header = ({ customAsciiArt, terminalWidth, }) => {
    let displayTitle;
    const widthOfLongLogo = getAsciiArtWidth(longAsciiLogo);
    if (customAsciiArt) {
        displayTitle = customAsciiArt;
    }
    else {
        displayTitle =
            terminalWidth >= widthOfLongLogo ? longAsciiLogo : shortAsciiLogo;
    }
    const artWidth = getAsciiArtWidth(displayTitle);
    return (_jsx(Box, { marginBottom: 1, alignItems: "flex-start", width: artWidth, flexShrink: 0, children: Colors.GradientColors ? (_jsx(Gradient, { colors: Colors.GradientColors, children: _jsx(Text, { children: displayTitle }) })) : (_jsx(Text, { children: displayTitle })) }));
};
//# sourceMappingURL=Header.js.map
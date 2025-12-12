//
//  LyricsPanel.mm
//  foo_sample
//
//  Test lyrics window for foobar2000 Mac
//

#import "stdafx.h"
#import "LyricsPanel.h"
#import "lyrics_display.h"
#import <vector>
#import <mutex>

// Configuration key constants
NSString * const kLyricsPanelFontSize = @"font-size";
NSString * const kLyricsPanelFontName = @"font-name";
NSString * const kLyricsPanelLineSpacing = @"line-spacing";

// Default values
static const CGFloat kDefaultFontSize = 14.0;
static const CGFloat kDefaultLineSpacing = 1.2;

// Panel instance tracking
static std::vector<__weak LyricsPanel*> g_panels;
static std::mutex g_panels_mutex;

// Class to hold a lyrics line with timestamp
@interface LyricLine : NSObject
@property (nonatomic) double timestamp;  // in seconds, -1 for non-timestamped
@property (nonatomic, strong) NSString *text;
@property (nonatomic) NSRange range;     // range in the attributed string
@end

@implementation LyricLine
@end

@interface LyricsPanel ()
@property (nonatomic, strong) NSTextView *lyricsTextView;
@property (nonatomic, strong) NSTextField *titleLabel;
@property (nonatomic, strong) NSMutableArray<LyricLine *> *lyricLines;
@property (nonatomic) BOOL hasSyncedLyrics;
@property (nonatomic) NSInteger currentLineIndex;
@property (nonatomic, strong) NSString *rawLyrics;
// Configuration properties
@property (nonatomic) CGFloat fontSize;
@property (nonatomic, strong) NSString *fontName;
@property (nonatomic) CGFloat lineSpacing;
@end

@implementation LyricsPanel

- (instancetype)init {
    return [self initWithConfiguration:nil];
}

- (instancetype)initWithConfiguration:(NSDictionary<NSString *, NSString *> *)config {
    self = [super initWithNibName:nil bundle:nil];
    if (self) {
        _lyricLines = [NSMutableArray new];
        _hasSyncedLyrics = NO;
        _currentLineIndex = -1;

        // Parse configuration with defaults
        _fontSize = kDefaultFontSize;
        _fontName = nil;  // nil means use system font
        _lineSpacing = kDefaultLineSpacing;

        if (config) {
            NSString *fontSizeStr = config[kLyricsPanelFontSize];
            if (fontSizeStr) {
                CGFloat size = [fontSizeStr doubleValue];
                if (size > 0) _fontSize = size;
            }

            NSString *fontNameStr = config[kLyricsPanelFontName];
            if (fontNameStr && fontNameStr.length > 0) {
                _fontName = fontNameStr;
            }

            NSString *lineSpacingStr = config[kLyricsPanelLineSpacing];
            if (lineSpacingStr) {
                CGFloat spacing = [lineSpacingStr doubleValue];
                if (spacing > 0) _lineSpacing = spacing;
            }
        }

        lyrics_display::register_panel(self);
    }
    return self;
}

- (void)dealloc {
    lyrics_display::unregister_panel(self);
}

// Helper to get the configured font
- (NSFont *)lyricsFont {
    if (_fontName) {
        NSFont *font = [NSFont fontWithName:_fontName size:_fontSize];
        if (font) return font;
    }
    return [NSFont systemFontOfSize:_fontSize];
}

- (NSFont *)lyricsBoldFont {
    if (_fontName) {
        NSFontManager *fontManager = [NSFontManager sharedFontManager];
        NSFont *font = [NSFont fontWithName:_fontName size:_fontSize + 1];
        if (font) {
            NSFont *boldFont = [fontManager convertFont:font toHaveTrait:NSBoldFontMask];
            if (boldFont) return boldFont;
        }
    }
    return [NSFont boldSystemFontOfSize:_fontSize + 1];
}

// Helper to create paragraph style with line spacing
- (NSParagraphStyle *)lyricsParagraphStyle {
    NSMutableParagraphStyle *style = [[NSMutableParagraphStyle alloc] init];
    style.lineSpacing = (_lineSpacing - 1.0) * _fontSize;  // Convert multiplier to points
    return style;
}

- (void)loadView {
    // Create main container view
    NSView *containerView = [[NSView alloc] initWithFrame:NSMakeRect(0, 0, 300, 400)];
    containerView.wantsLayer = YES;
    containerView.layer.backgroundColor = [[NSColor windowBackgroundColor] CGColor];
    self.view = containerView;
}

- (void)viewDidLoad {
    [super viewDidLoad];

    [self setupUI];
}

- (void)setupUI {
    // Title label
    _titleLabel = [[NSTextField alloc] initWithFrame:NSZeroRect];
    _titleLabel.stringValue = @"Lyrics";
    _titleLabel.font = [NSFont boldSystemFontOfSize:16];
    _titleLabel.bordered = NO;
    _titleLabel.editable = NO;
    _titleLabel.selectable = NO;
    _titleLabel.backgroundColor = [NSColor clearColor];
    _titleLabel.textColor = [NSColor labelColor];
    _titleLabel.translatesAutoresizingMaskIntoConstraints = NO;
    // Enable text wrapping
    _titleLabel.lineBreakMode = NSLineBreakByWordWrapping;
    _titleLabel.cell.wraps = YES;
    _titleLabel.preferredMaxLayoutWidth = 0;  // Will be set by constraints
    [_titleLabel setContentCompressionResistancePriority:NSLayoutPriorityDefaultLow forOrientation:NSLayoutConstraintOrientationHorizontal];
    [_titleLabel setContentHuggingPriority:NSLayoutPriorityDefaultHigh forOrientation:NSLayoutConstraintOrientationVertical];
    [self.view addSubview:_titleLabel];

    // Scroll view for lyrics text
    NSScrollView *scrollView = [[NSScrollView alloc] initWithFrame:NSZeroRect];
    scrollView.hasVerticalScroller = YES;
    scrollView.hasHorizontalScroller = NO;
    scrollView.autohidesScrollers = YES;
    scrollView.borderType = NSBezelBorder;
    scrollView.translatesAutoresizingMaskIntoConstraints = NO;
    [self.view addSubview:scrollView];

    // Text view for lyrics content
    _lyricsTextView = [[NSTextView alloc] initWithFrame:NSZeroRect];
    _lyricsTextView.editable = NO;
    _lyricsTextView.selectable = YES;
    _lyricsTextView.font = [self lyricsFont];
    _lyricsTextView.textColor = [NSColor textColor];
    _lyricsTextView.backgroundColor = [NSColor textBackgroundColor];
    _lyricsTextView.autoresizingMask = NSViewWidthSizable | NSViewHeightSizable;
    _lyricsTextView.textContainerInset = NSMakeSize(10, 10);

    // Apply default paragraph style with line spacing
    _lyricsTextView.defaultParagraphStyle = [self lyricsParagraphStyle];

    // Set placeholder text
    _lyricsTextView.string = @"No lyrics loaded.\n\nLyrics will appear here when a track with lyrics is playing.";

    scrollView.documentView = _lyricsTextView;

    // Layout constraints
    [NSLayoutConstraint activateConstraints:@[
        // Title label
        [_titleLabel.topAnchor constraintEqualToAnchor:self.view.topAnchor constant:12],
        [_titleLabel.leadingAnchor constraintEqualToAnchor:self.view.leadingAnchor constant:12],
        [_titleLabel.trailingAnchor constraintEqualToAnchor:self.view.trailingAnchor constant:-12],

        // Scroll view
        [scrollView.topAnchor constraintEqualToAnchor:_titleLabel.bottomAnchor constant:8],
        [scrollView.leadingAnchor constraintEqualToAnchor:self.view.leadingAnchor constant:12],
        [scrollView.trailingAnchor constraintEqualToAnchor:self.view.trailingAnchor constant:-12],
        [scrollView.bottomAnchor constraintEqualToAnchor:self.view.bottomAnchor constant:-12],
    ]];
}

// Parse timestamp from LRC format [mm:ss.xx] and return seconds, or -1 if not a timestamp
- (double)parseTimestamp:(NSString *)tag {
    NSRegularExpression *regex = [NSRegularExpression regularExpressionWithPattern:@"^\\[(\\d{1,2}):(\\d{2})(?:[.:](\\d{1,3}))?\\]$"
                                                                           options:0
                                                                             error:nil];
    NSTextCheckingResult *match = [regex firstMatchInString:tag options:0 range:NSMakeRange(0, tag.length)];
    if (!match) return -1;

    NSInteger minutes = [[tag substringWithRange:[match rangeAtIndex:1]] integerValue];
    NSInteger seconds = [[tag substringWithRange:[match rangeAtIndex:2]] integerValue];
    double fraction = 0;

    if ([match rangeAtIndex:3].location != NSNotFound) {
        NSString *fracStr = [tag substringWithRange:[match rangeAtIndex:3]];
        // Handle both .xx (centiseconds) and .xxx (milliseconds)
        fraction = [fracStr doubleValue] / (fracStr.length == 3 ? 1000.0 : 100.0);
    }

    return minutes * 60.0 + seconds + fraction;
}

// Check if lyrics contain LRC timestamps
- (BOOL)isLRCFormat:(NSString *)lyrics {
    NSRegularExpression *regex = [NSRegularExpression regularExpressionWithPattern:@"^\\[\\d{1,2}:\\d{2}[.:]\\d{1,3}\\]"
                                                                           options:NSRegularExpressionAnchorsMatchLines
                                                                             error:nil];
    NSUInteger matches = [regex numberOfMatchesInString:lyrics options:0 range:NSMakeRange(0, lyrics.length)];
    return matches >= 3;  // At least 3 timestamped lines to consider it LRC
}

- (void)setLyricsText:(NSString *)text {
    if (!_lyricsTextView) return;

    _rawLyrics = text;
    [_lyricLines removeAllObjects];
    _currentLineIndex = -1;

    if (!text || text.length == 0) {
        _lyricsTextView.string = @"";
        _hasSyncedLyrics = NO;
        return;
    }

    // Check if this is LRC format
    _hasSyncedLyrics = [self isLRCFormat:text];

    if (!_hasSyncedLyrics) {
        // Plain lyrics - display as-is
        _lyricsTextView.string = text;
        [_lyricsTextView scrollRangeToVisible:NSMakeRange(0, 0)];
        return;
    }

    // Parse LRC format and build attributed string
    NSMutableAttributedString *attrString = [[NSMutableAttributedString alloc] init];
    NSArray *lines = [text componentsSeparatedByString:@"\n"];

    NSDictionary *normalAttrs = @{
        NSFontAttributeName: [self lyricsFont],
        NSForegroundColorAttributeName: [NSColor secondaryLabelColor],
        NSParagraphStyleAttributeName: [self lyricsParagraphStyle]
    };

    NSRegularExpression *tagRegex = [NSRegularExpression regularExpressionWithPattern:@"\\[([^\\]]+)\\]"
                                                                              options:0
                                                                                error:nil];

    for (NSString *line in lines) {
        // Extract all tags from the line
        NSArray<NSTextCheckingResult *> *matches = [tagRegex matchesInString:line options:0 range:NSMakeRange(0, line.length)];

        double timestamp = -1;
        NSUInteger textStart = 0;

        for (NSTextCheckingResult *match in matches) {
            NSString *tag = [line substringWithRange:match.range];
            double ts = [self parseTimestamp:tag];
            if (ts >= 0) {
                timestamp = ts;
                textStart = NSMaxRange(match.range);
            }
        }

        // Get the text after the last timestamp tag
        NSString *lineText = (textStart < line.length) ? [line substringFromIndex:textStart] : @"";
        lineText = [lineText stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];

        // Skip metadata tags like [ar:Artist], [ti:Title], etc.
        if (timestamp < 0 && lineText.length == 0) {
            continue;
        }

        // Skip empty lines with timestamps (instrumental sections)
        if (lineText.length == 0) {
            lineText = @"♪";  // Musical note for instrumental
        }

        NSRange lineRange = NSMakeRange(attrString.length, lineText.length);

        // Store line info
        LyricLine *lyricLine = [[LyricLine alloc] init];
        lyricLine.timestamp = timestamp;
        lyricLine.text = lineText;
        lyricLine.range = lineRange;
        [_lyricLines addObject:lyricLine];

        // Add to attributed string
        NSAttributedString *attrLine = [[NSAttributedString alloc] initWithString:lineText attributes:normalAttrs];
        [attrString appendAttributedString:attrLine];
        [attrString appendAttributedString:[[NSAttributedString alloc] initWithString:@"\n" attributes:normalAttrs]];
    }

    // Sort by timestamp
    [_lyricLines sortUsingComparator:^NSComparisonResult(LyricLine *a, LyricLine *b) {
        if (a.timestamp < b.timestamp) return NSOrderedAscending;
        if (a.timestamp > b.timestamp) return NSOrderedDescending;
        return NSOrderedSame;
    }];

    // Rebuild attributed string in sorted order
    attrString = [[NSMutableAttributedString alloc] init];
    for (NSUInteger i = 0; i < _lyricLines.count; i++) {
        LyricLine *line = _lyricLines[i];

        NSRange newRange = NSMakeRange(attrString.length, line.text.length);
        line.range = newRange;

        NSAttributedString *attrLine = [[NSAttributedString alloc] initWithString:line.text attributes:normalAttrs];
        [attrString appendAttributedString:attrLine];
        if (i < _lyricLines.count - 1) {
            [attrString appendAttributedString:[[NSAttributedString alloc] initWithString:@"\n" attributes:normalAttrs]];
        }
    }

    [[_lyricsTextView textStorage] setAttributedString:attrString];
    [_lyricsTextView scrollRangeToVisible:NSMakeRange(0, 0)];
}

- (void)updatePlaybackTime:(double)seconds {
    if (!_hasSyncedLyrics || _lyricLines.count == 0) return;

    // Find the current line based on timestamp
    NSInteger newLineIndex = -1;
    for (NSInteger i = _lyricLines.count - 1; i >= 0; i--) {
        LyricLine *line = _lyricLines[i];
        if (line.timestamp >= 0 && seconds >= line.timestamp) {
            newLineIndex = i;
            break;
        }
    }

    if (newLineIndex == _currentLineIndex) return;

    NSTextStorage *textStorage = [_lyricsTextView textStorage];

    // Reset previous line to normal style
    if (_currentLineIndex >= 0 && _currentLineIndex < (NSInteger)_lyricLines.count) {
        LyricLine *prevLine = _lyricLines[_currentLineIndex];
        if (prevLine.range.location + prevLine.range.length <= textStorage.length) {
            [textStorage addAttributes:@{
                NSFontAttributeName: [self lyricsFont],
                NSForegroundColorAttributeName: [NSColor secondaryLabelColor]
            } range:prevLine.range];
        }
    }

    _currentLineIndex = newLineIndex;

    // Highlight current line
    if (_currentLineIndex >= 0) {
        LyricLine *currentLine = _lyricLines[_currentLineIndex];
        if (currentLine.range.location + currentLine.range.length <= textStorage.length) {
            [textStorage addAttributes:@{
                NSFontAttributeName: [self lyricsBoldFont],
                NSForegroundColorAttributeName: [NSColor labelColor]
            } range:currentLine.range];

            // Scroll to make current line visible
            [_lyricsTextView scrollRangeToVisible:currentLine.range];
        }
    }
}

- (void)setTrackTitle:(NSString *)title {
    if (_titleLabel) {
        _titleLabel.stringValue = title ?: @"Lyrics";
    }
}

@end

#pragma mark - lyrics_display implementation

namespace lyrics_display {

void register_panel(LyricsPanel* panel) {
    std::lock_guard<std::mutex> lock(g_panels_mutex);
    g_panels.push_back(panel);
}

void unregister_panel(LyricsPanel* panel) {
    std::lock_guard<std::mutex> lock(g_panels_mutex);
    g_panels.erase(
        std::remove_if(g_panels.begin(), g_panels.end(),
            [panel](LyricsPanel* p) { return p == nil || p == panel; }),
        g_panels.end()
    );
}

void set_lyrics(const std::string& artist, const std::string& title, const std::string& lyrics) {
    NSString *nsArtist = [NSString stringWithUTF8String:artist.c_str()];
    NSString *nsTitle = [NSString stringWithUTF8String:title.c_str()];
    NSString *nsLyrics = [NSString stringWithUTF8String:lyrics.c_str()];
    NSString *displayTitle = [NSString stringWithFormat:@"%@ - %@", nsArtist, nsTitle];

    // Must run on main thread for UI updates
    dispatch_async(dispatch_get_main_queue(), ^{
        std::lock_guard<std::mutex> lock(g_panels_mutex);
        // Clean up nil references and update panels
        g_panels.erase(
            std::remove_if(g_panels.begin(), g_panels.end(),
                [](LyricsPanel* p) { return p == nil; }),
            g_panels.end()
        );

        for (LyricsPanel* panel : g_panels) {
            if (panel) {
                [panel setTrackTitle:displayTitle];
                [panel setLyricsText:nsLyrics];
            }
        }
    });
}

void clear() {
    dispatch_async(dispatch_get_main_queue(), ^{
        std::lock_guard<std::mutex> lock(g_panels_mutex);
        for (LyricsPanel* panel : g_panels) {
            if (panel) {
                [panel setTrackTitle:@"Lyrics"];
                [panel setLyricsText:@"No lyrics loaded."];
            }
        }
    });
}

void update_time(double seconds) {
    dispatch_async(dispatch_get_main_queue(), ^{
        std::lock_guard<std::mutex> lock(g_panels_mutex);
        for (LyricsPanel* panel : g_panels) {
            if (panel) {
                [panel updatePlaybackTime:seconds];
            }
        }
    });
}

} // namespace lyrics_display

#pragma mark - ui_element_mac implementation

namespace {

class ui_element_lyrics : public ui_element_mac {
public:
    service_ptr instantiate(service_ptr arg) override {
        // Extract configuration dictionary from arg if provided
        NSDictionary<NSString *, NSString *> *config = nil;
        if (arg.is_valid()) {
            id obj = fb2k::unwrapNSObject(arg);
            if ([obj isKindOfClass:[NSDictionary class]]) {
                config = (NSDictionary<NSString *, NSString *> *)obj;
            }
        }
        LyricsPanel *panel = [[LyricsPanel alloc] initWithConfiguration:config];
        return fb2k::wrapNSObject(panel);
    }

    bool match_name(const char *name) override {
        return strcmp(name, "lyrics_panel") == 0 || strcmp(name, "Lyrics") == 0;
    }

    fb2k::stringRef get_name() override {
        return fb2k::makeString("Lyrics Panel");
    }

    GUID get_guid() override {
        // {A1B2C3D4-E5F6-4789-ABCD-EF0123456789}
        return GUID{ 0xa1b2c3d4, 0xe5f6, 0x4789, { 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89 } };
    }
};

FB2K_SERVICE_FACTORY(ui_element_lyrics);

} // namespace

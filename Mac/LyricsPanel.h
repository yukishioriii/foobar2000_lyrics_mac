//
//  LyricsPanel.h
//  foo_sample
//
//  Test lyrics window for foobar2000 Mac
//

#import <Cocoa/Cocoa.h>

// Configuration keys for layout editor arguments
extern NSString * const kLyricsPanelFontSize;      // e.g., "14" (points)
extern NSString * const kLyricsPanelFontName;      // e.g., "Helvetica"
extern NSString * const kLyricsPanelLineSpacing;   // e.g., "1.5" (multiplier)

@interface LyricsPanel : NSViewController

- (instancetype)initWithConfiguration:(NSDictionary<NSString *, NSString *> *)config;

- (void)setLyricsText:(NSString *)text;
- (void)setTrackTitle:(NSString *)title;
- (void)updatePlaybackTime:(double)seconds;

@end

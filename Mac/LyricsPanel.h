//
//  LyricsPanel.h
//  foo_sample
//
//  Test lyrics window for foobar2000 Mac
//

#import <Cocoa/Cocoa.h>

@interface LyricsPanel : NSViewController

- (void)setLyricsText:(NSString *)text;
- (void)setTrackTitle:(NSString *)title;
- (void)updatePlaybackTime:(double)seconds;

@end

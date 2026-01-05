//
//  GroupedPlaylistPanel.h
//  foo_sample
//
//  Demonstrates NSTableView with album grouping and album art
//  Similar to foobar2000's playlist view with group separators
//

#import <Cocoa/Cocoa.h>

@class GroupedPlaylistPanel;

// Custom table view to handle keyboard events
@interface PlaylistTableView : NSTableView
@property (nonatomic, weak) GroupedPlaylistPanel *playlistPanel;
@end

@interface GroupedPlaylistPanel : NSViewController <NSTableViewDataSource, NSTableViewDelegate, NSTableViewDataSource>

- (void)playSelectedTrack;
- (void)deleteSelectedTracks;

@end

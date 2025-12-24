#pragma once

#ifdef __OBJC__
#import <Cocoa/Cocoa.h>

@interface StatusBarNowPlaying : NSObject

+ (instancetype)shared;

- (void)updateTrack:(NSString *)artist title:(NSString *)title;
- (void)updatePlaybackState:(BOOL)isPlaying isPaused:(BOOL)isPaused;
- (void)clearTrack;

@end

#endif

// C++ interface for use from playback callbacks
namespace statusbar_nowplaying {
    void update_track(const char* artist, const char* title);
    void update_playback_state(bool is_playing, bool is_paused);
    void clear();
    void initialize();
    void shutdown();
    void refresh_playlist_cache();
    void set_visible(bool visible);
}

// Check if status bar is enabled (defined in contextmenu.cpp)
bool is_status_bar_enabled();

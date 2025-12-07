#pragma once

// Cross-platform lyrics display interface
// Used to send lyrics from search results to the UI panel

#include <string>

// Forward declaration for Objective-C (must be at global scope)
#ifdef __OBJC__
@class LyricsPanel;
#endif

namespace lyrics_display {

// Update the lyrics panel with new content
// Can be called from any thread - will dispatch to main thread internally
void set_lyrics(const std::string& artist, const std::string& title, const std::string& lyrics);

// Update playback time (for synced lyrics highlighting)
void update_time(double seconds);

// Clear the lyrics panel
void clear();

// Register/unregister panel instances (called by UI element implementations)
// Only available in Objective-C++ files
#ifdef __OBJC__
void register_panel(LyricsPanel* panel);
void unregister_panel(LyricsPanel* panel);
#endif

} // namespace lyrics_display

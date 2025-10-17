package com.movieapp.movie;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import java.util.List;
import org.springframework.security.core.Authentication;
import com.movieapp.auth.UserService;
import com.movieapp.auth.User;

@RestController
@RequestMapping("/api/movies")

public class MovieController {
    @Autowired
    private MovieService movieService;

    @Autowired
    private UserService userService;

    @GetMapping
    public List<Movie> getAllMovies() {
        return movieService.getAllMovies();
    }

    @GetMapping("/{id}")
    public ResponseEntity<Movie> getMovieById(@PathVariable Long id) {
        return movieService.getMovieById(id)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    @PostMapping
    public ResponseEntity<?> createMovie(@RequestBody Movie movie, Authentication authentication) {
        String username = authentication.getName();
        User user = userService.findByUsername(username).orElse(null);
        if (user == null || !"ADMIN".equals(user.getUserType())) {
            return ResponseEntity.status(403).body("Only admin users can add movies.");
        }
        return ResponseEntity.ok(movieService.createMovie(movie));
    }


    @PutMapping("/{id}")
    public ResponseEntity<?> updateMovie(@PathVariable Long id, @RequestBody Movie movie, Authentication authentication) {
        String username = authentication.getName();
        User user = userService.findByUsername(username).orElse(null);
        if (user == null || !"ADMIN".equals(user.getUserType())) {
            return ResponseEntity.status(403).body("Only admin users can edit movies.");
        }
        try {
            return ResponseEntity.ok(movieService.updateMovie(id, movie));
        } catch (RuntimeException e) {
            return ResponseEntity.notFound().build();
        }
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<?> deleteMovie(@PathVariable Long id, Authentication authentication) {
        String username = authentication.getName();
        User user = userService.findByUsername(username).orElse(null);
        if (user == null || !"ADMIN".equals(user.getUserType())) {
            return ResponseEntity.status(403).body("Only admin users can delete movies.");
        }
        movieService.deleteMovie(id);
        return ResponseEntity.noContent().build();
    }
}

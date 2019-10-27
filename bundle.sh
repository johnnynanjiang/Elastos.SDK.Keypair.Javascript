browserify index.js --standalone elastosjs -o elastos-1.0.9.js
terser --compress -- elastos-1.0.9.js > elastos-1.0.9.min.js
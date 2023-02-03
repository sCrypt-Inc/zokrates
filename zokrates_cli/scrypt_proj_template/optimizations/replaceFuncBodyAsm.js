const fs = require("fs");

const file = process.argv[2];
const funcName = process.argv[3];
const fileAsm = process.argv[4];

const asm = fs.readFileSync(fileAsm, "utf8");

// Buffer to store the characters
let buffer = "";

let pattern = "function " + funcName;
let patternHits = 0;
let matchActive = false;
let curlyBraceLevel = 0;

// Open the file in read-only mode
const fileStream = fs.createReadStream(file, {
  encoding: "utf8",
});

// Listen for the data event
fileStream.on("data", (chunk) => {
  for (let i = 0; i < chunk.length; i++) {
    let c = chunk[i];

    if (matchActive) {
      if (curlyBraceLevel == 0) {
        // Function args
        buffer += c;
      }
      if (c == "{") {
        curlyBraceLevel += 1;
        if (curlyBraceLevel == 1) {
          // First opening curly brace
          // Add ASM here
          buffer += " asm { ";
          buffer += asm;
          buffer += "}";
        }
      } else if (c == "}") {
        if (curlyBraceLevel == 1) {
          // Closing function curly brace
          buffer += c;
          matchActive = false;
        } else {
          curlyBraceLevel -= 1;
        }
      }
    } else if (c == pattern[patternHits]) {
      patternHits += 1;
      buffer += c;

      // Check if full pattern match
      if (patternHits == pattern.length) {
        matchActive = true;
      }
    } else {
      patternHits = 0;
      buffer += c;
    }
  }
});

// Listen for the end event
fileStream.on("end", () => {
  console.log(buffer);
});

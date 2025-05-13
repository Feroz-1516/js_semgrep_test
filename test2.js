// This is a normal-looking JavaScript function with a hidden bidirectional character
function checkAccess(user) {
    // The following line contains an RLO (Right-to-Left Override) character
    // ‮ (U+202E) which is invisible but reverses text direction
    if (user.role === "‮admin") { // This will visually show "admin" but actually checks for "nimda"
        console.log("Access granted");
        return true;
    } else {
        console.log("Access denied");
        return false;
    }
}

// Example usage
const user = {
    name: "John",
    role: "admin"  // This is "admin", but due to the RLO character, the check will fail
};

// The user might look like they should get access, but they won't
checkAccess(user);

// This vulnerable pattern makes code reviews dangerous
// because what the code reviewer sees is different from what the compiler processes

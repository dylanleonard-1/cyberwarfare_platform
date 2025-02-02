document.addEventListener("DOMContentLoaded", function() {
    let redScore = 0;
    let blueScore = 0;

    function updateScore(team, points) {
        if (team === "red") {
            redScore += points;
            document.getElementById("red-score").innerText = redScore;
        } else {
            blueScore += points;
            document.getElementById("blue-score").innerText = blueScore;
        }
    }

    // Example: Red team gains points for successful attack
    setTimeout(() => updateScore("red", 10), 5000);
    setTimeout(() => updateScore("blue", 5), 7000);
});

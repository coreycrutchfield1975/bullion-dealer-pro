async function fetchMetals() {
  try {
    const res = await fetch("/api/metals");
    const data = await res.json();

    document.getElementById("gold").innerText = "Gold: $" + data.gold;
    document.getElementById("silver").innerText = "Silver: $" + data.silver;
    document.getElementById("platinum").innerText = "Platinum: $" + data.platinum;
    document.getElementById("palladium").innerText = "Palladium: $" + data.palladium;
  } catch (err) {
    console.error(err);
  }
}

function calc() {
  const buy = parseFloat(document.getElementById("buy").value || 0);
  const sell = parseFloat(document.getElementById("sell").value || 0);

  document.getElementById("spread").innerText =
    "Spread: " + (sell - buy).toFixed(2) + "%";
}

fetchMetals();

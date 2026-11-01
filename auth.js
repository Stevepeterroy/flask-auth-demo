async function auth(event, action) {
  event.preventDefault();
  const message = document.getElementById("message");
  try {
    const session = await fetch("/api/session").then((r) => r.json());
    const response = await fetch("/api/" + action, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-CSRF-Token": session.csrf,
      },
      body: JSON.stringify({
        username: document.getElementById("username").value,
        password: document.getElementById("password").value,
      }),
    });
    const data = await response.json();
    message.textContent = response.ok
      ? action === "signup"
        ? "Account created. Sign in using the link below."
        : "Signed in to the local learning demo."
      : data.error;
    message.style.color = response.ok ? "#246044" : "#9c2635";
  } catch (error) {
    message.textContent =
      "Unable to connect. Start app.py and open http://127.0.0.1:5001/signup.html";
  }
}
function handleSignup(event) {
  return auth(event, "signup");
}
function handleLogin(event) {
  return auth(event, "login");
}

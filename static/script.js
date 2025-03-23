const API_URL = "http://127.0.0.1:5000";

// ✅ Check if user is logged in (on page load)
window.onload = function () {
    fetch(`${API_URL}/me`, { credentials: "include" })
        .then(response => response.json())
        .then(data => {
            if (data.logged_in) {
                showExpenseSection();
                getExpenses();
            }
        })
        .catch(error => console.error("Error:", error));
};

// ✅ Show expense section
function showExpenseSection() {
    document.getElementById("auth-section").style.display = "none";
    document.getElementById("expense-section").style.display = "block";
}

// ✅ Login Function
function login() {
    const email = document.getElementById("email").value;
    const password = document.getElementById("password").value;

    fetch(`${API_URL}/login`, {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password })
    })
    .then(response => response.json())
    .then(data => {
        alert(data.message);
        if (data.message === "Login successful") {
            showExpenseSection();
            getExpenses();
        }
    })
    .catch(error => console.error("Error:", error));
}

// ✅ Logout Function
function logout() {
    fetch(`${API_URL}/logout`, {
        method: "POST",
        credentials: "include"
    })
    .then(response => response.json())
    .then(data => {
        alert(data.message);
        document.getElementById("auth-section").style.display = "block";
        document.getElementById("expense-section").style.display = "none";
    })
    .catch(error => console.error("Error:", error));
}

// ✅ Add Expense Function
function addExpense() {
    const amount = document.getElementById("amount").value;
    const category = document.getElementById("category").value;
    const description = document.getElementById("description").value;
    const date = document.getElementById("date").value;

    fetch(`${API_URL}/expenses`, {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ amount, category, description, date })
    })
    .then(response => response.json())
    .then(data => {
        alert(data.message);
        getExpenses(); // Refresh the list
    })
    .catch(error => console.error("Error:", error));
}

// ✅ Fetch and Display Expenses
function getExpenses() {
    fetch(`${API_URL}/expenses`, { credentials: "include" })
    .then(response => response.json())
    .then(expenses => {
        const expenseList = document.getElementById("expense-list");
        expenseList.innerHTML = "";
        expenses.forEach(expense => {
            const li = document.createElement("li");
            li.textContent = `${expense.date}: ₹${expense.amount} - ${expense.category} (${expense.description})`;
            expenseList.appendChild(li);
        });
    })
    .catch(error => console.error("Error:", error));
}

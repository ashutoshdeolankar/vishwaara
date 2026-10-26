/* Vishwaara: login helper shared by every page.
   The login token is kept in this browser (localStorage) and sent to the
   API as "Authorization: Bearer <token>". */

const TravelPalAuth = (function () {

    const API_BASE = "http://localhost:8000";
    const STORAGE_KEY = "travelpal_session";

    function read() {
        try {
            return JSON.parse(localStorage.getItem(STORAGE_KEY));
        } catch (error) {
            return null;
        }
    }

    function write(session) {
        try {
            localStorage.setItem(STORAGE_KEY, JSON.stringify(session));
        } catch (error) {
            /* storage blocked: the user simply stays logged out */
        }
    }

    function clear() {
        try {
            localStorage.removeItem(STORAGE_KEY);
        } catch (error) {
            /* nothing to clear */
        }
    }

    function token() {
        const session = read();
        return session && session.token ? session.token : null;
    }

    function user() {
        const session = read();
        return session && session.user ? session.user : null;
    }

    function isLoggedIn() {
        return token() !== null;
    }

    function messageFrom(data, status) {
        const detail = data && data.detail;
        if (typeof detail === "string") {
            return detail;
        }
        if (Array.isArray(detail)) {
            return detail
                .map(item => String(item.msg || "").replace(/^Value error, /, ""))
                .filter(Boolean)
                .join(" ") || "Please check the details you entered.";
        }
        if (status === 429) {
            return "Too many requests. Please wait a minute and try again.";
        }
        return "Something went wrong (" + status + ").";
    }

    async function request(method, path, body) {

        const headers = { "Content-Type": "application/json" };
        if (token()) {
            headers.Authorization = "Bearer " + token();
        }

        let response;
        try {
            response = await fetch(API_BASE + path, {
                method: method,
                headers: headers,
                body: body === undefined ? undefined : JSON.stringify(body)
            });
        } catch (error) {
            throw new Error(
                "Could not reach the Vishwaara server. Is Docker running?"
            );
        }

        let data = null;
        try {
            data = await response.json();
        } catch (error) {
            data = null;
        }

        if (response.status === 401 && token()) {
            clear();            /* session ended or expired */
            updateNav();
        }

        if (!response.ok) {
            throw new Error(messageFrom(data, response.status));
        }

        return data;
    }

    /* a small maths question that proves you are a person */
    function getCaptcha() {
        return request("GET", "/auth/captcha");
    }

    async function register(name, email, password, homeCity, captcha) {
        const data = await request("POST", "/auth/register", {
            name: name,
            email: email,
            password: password,
            home_city: homeCity || null,
            captcha_token: captcha ? captcha.token : "",
            captcha_answer: captcha ? captcha.answer : ""
        });
        if (data.needs_code) {
            return { needsCode: true, email: data.email };
        }
        write({ token: data.token, user: data.user });
        return data.user;
    }

    async function login(email, password, captcha) {
        const data = await request("POST", "/auth/login", {
            email: email,
            password: password,
            captcha_token: captcha ? captcha.token : "",
            captcha_answer: captcha ? captcha.answer : ""
        });
        if (data.needs_code) {
            return { needsCode: true, email: data.email };
        }
        write({ token: data.token, user: data.user });
        return data.user;
    }

    /* the 6-digit code that was emailed after sign up / password check */
    async function verifyCode(email, code) {
        const data = await request("POST", "/auth/verify", { email: email, code: code });
        write({ token: data.token, user: data.user });
        return data.user;
    }

    function resendCode(email) {
        return request("POST", "/auth/resend", { email: email });
    }

    async function logout() {
        try {
            await request("POST", "/auth/logout");
        } catch (error) {
            /* even if the server is off, log out in this browser */
        }
        clear();
        updateNav();
    }

    function saveUser(newUser) {
        const session = read();
        if (session) {
            session.user = newUser;
            write(session);
        }
    }

    /* Only same-folder .html pages are allowed as a "go back to" address */
    function safeNext(value) {
        return /^[A-Za-z0-9_\-]+\.html(#[A-Za-z0-9_\-]*)?$/.test(value || "")
            ? value
            : "index.html";
    }

    function requireLogin() {
        if (!isLoggedIn()) {
            const here = window.location.pathname.split("/").pop() || "index.html";
            window.location.replace(
                "login.html?next=" + encodeURIComponent(safeNext(here))
            );
            return false;
        }
        return true;
    }

    /* Fills <li id="navAuth"> with Login, or My Trips + Logout */
    function updateNav() {

        const holder = document.getElementById("navAuth");
        if (!holder) {
            return;
        }

        holder.innerHTML = "";

        if (isLoggedIn()) {

            const current = user();
            const firstName = current && current.name
                ? current.name.split(" ")[0]
                : "";

            const trips = document.createElement("a");
            trips.className = "nav-link";
            trips.href = "my-trips.html";
            trips.textContent = firstName ? firstName + "'s Trips" : "My Trips";

            const out = document.createElement("a");
            out.className = "nav-link";
            out.href = "#";
            out.textContent = "Logout";
            out.addEventListener("click", async function (event) {
                event.preventDefault();
                await logout();
                window.location.href = "index.html";
            });

            holder.style.display = "flex";
            holder.appendChild(trips);
            holder.appendChild(out);

        } else {

            const link = document.createElement("a");
            link.className = "nav-link";
            link.href = "login.html";
            link.textContent = "Login";
            holder.appendChild(link);

        }
    }

    document.addEventListener("DOMContentLoaded", updateNav);

    return {
        request: request,
        getCaptcha: getCaptcha,
        verifyCode: verifyCode,
        resendCode: resendCode,
        register: register,
        login: login,
        logout: logout,
        isLoggedIn: isLoggedIn,
        user: user,
        saveUser: saveUser,
        safeNext: safeNext,
        requireLogin: requireLogin,
        updateNav: updateNav
    };

})();

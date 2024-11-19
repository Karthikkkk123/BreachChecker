import requests
import hashlib
import re
import streamlit as st


# ANSI escape codes for colors (will not be used in Streamlit, just for debugging)
class colors:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    RESET = "\033[0m"


st.set_page_config(
    page_title=" Sagittarius",  # Set page title
    page_icon=r"🔒",  # Favicon emoji
    layout="centered",
)

# Initialize the active page in session state
if "active_page" not in st.session_state:
    st.session_state.active_page = "Dashboard"

# Sidebar navigation
if st.sidebar.button("Dashboard"):
    st.session_state.active_page = "Dashboard"
if st.sidebar.button("FAQs"):
    st.session_state.active_page = "FAQs"


# Email Breach Check - LeakCheck
def req_leakcheck(email):
    url = f"https://leakcheck.io/api/public?check={email}"
    try:
        response = requests.get(url)
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 404:
            return {"sources": []}
        else:
            st.error(
                f"LeakCheck API call failed with status code {response.status_code}"
            )
            return False
    except Exception as e:
        st.error(f"Error: {e}")
        return False


# Email Breach Check - XposedOrNot
def req_xposedornot(email):
    url = f"https://api.xposedornot.com/v1/check-email/{email}"
    try:
        response = requests.get(url)
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 404:
            return {"breaches": []}
        else:
            st.error(
                f"XposedOrNot API call failed with status code {response.status_code}"
            )
            return False
    except Exception as e:
        st.error(f"Error: {e}")
        return False


# Password Breach Check - HaveIBeenPwned (HIBP)
def check_pwned_password(password):
    sha1_hash = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix = sha1_hash[:5]
    suffix = sha1_hash[5:]
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    try:
        response = requests.get(url)
        if response.status_code == 200:
            hashes = (line.split(":") for line in response.text.splitlines())
            for h, count in hashes:
                if h == suffix:
                    st.error(f"Password has been pwned {count} times!")
                    return True
            st.success("Password is safe!")
            return False
        else:
            st.error("Error fetching data from HIBP.")
            return False
    except Exception as e:
        st.error(f"Error: {e}")
        return False


# Function to print email breach results
def print_email_breaches(answer, source_name):
    breaches = (
        answer.get("sources", [])
        if source_name == "LeakCheck"
        else answer.get("breaches", [])
    )
    if not breaches:
        st.warning(f"No breaches found for the email in {source_name}.")
        return

    st.success(f"Found email in {len(breaches)} breaches from {source_name}.")

    for breach in breaches:
        # Handle cases where breach is a list (e.g., ['BigBasket'])
        if isinstance(breach, list):
            breach_name = breach[0] if len(breach) > 0 else "Unknown"
            date = "Unknown"
        elif isinstance(breach, dict):
            breach_name = breach.get("name", "Unknown")
            date = breach.get("date", "Unknown")
        elif isinstance(breach, str):
            breach_name = breach
            date = "Unknown"
        else:
            st.warning(f"Unexpected breach data format: {breach}")
            continue

        st.write(f"Breach: {breach_name}, Date: {date}")


# Main function to display Streamlit interface
def main():
    # App title and description
    st.title("Password & Email Breach Checker")
    st.write(
        "This tool helps you check if your email or password has been involved in a known data breach."
    )

    # Main content rendering based on the active page
    if st.session_state.active_page == "Dashboard":
        st.title("Dashboard")

        # Email input
        email = st.text_input("Enter your email address:", key="email_input")
        email_validation = re.match(r"[^@]+@[^@]+\.[^@]+", email)
        password = st.text_input("Enter your password", "", type="password")

        # Check button to trigger breach checks
        if st.button("Check for Breaches"):
            if not email_validation:
                st.error("Please enter a valid email address.")

            if email_validation:
                # Email breach checks
                st.subheader("Checking email breaches...")
                leakcheck_result = req_leakcheck(email)
                if leakcheck_result:
                    print_email_breaches(leakcheck_result, "LeakCheck")

                xposed_result = req_xposedornot(email)
                if xposed_result:
                    print_email_breaches(xposed_result, "XposedOrNot")

            if password:
                # Password breach checks
                st.subheader("Checking password breaches...")
                check_pwned_password(password)

    elif st.session_state.active_page == "FAQs":
        st.title("Frequently Asked Questions")

        # FAQ Section
        faq_items = {
            "What exactly is a data breach?": "A data breach is an incident where sensitive, confidential, or protected information is accessed or disclosed without authorization.",
            "I just found out I’m in a data breach. What do I do next?": "Start by changing your passwords immediately, monitor your accounts for suspicious activity, and consider enabling multi-factor authentication.",
            "What information gets exposed in data breaches?": "Typically, breaches expose personal information like emails, passwords, financial data, or social security numbers.",
        }

        for question, answer in faq_items.items():
            with st.expander(question):
                st.write(answer)

    # Footer rendering
    st.markdown(
        """
        <footer>
            <a href="#" onclick="alert('Terms and Conditions will go here.')">Terms and Conditions</a>
            <a href="https://github.com" target="_blank">GitHub</a>
        </footer>
    """,
        unsafe_allow_html=True,
    )


if __name__ == "__main__":
    main()

/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  darkMode: "class",
  theme: {
    extend: {
      colors: {
        sev: {
          critical: "#b00020",
          high: "#e65100",
          medium: "#f9a825",
          low: "#0277bd",
          info: "#616161",
        },
      },
    },
  },
  plugins: [],
};

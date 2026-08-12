/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
  theme: {
    extend: {
      colors: {
        ink: "#08111f",
        panel: "#0e1a2c",
        line: "#1f3553",
        cyan: "#49d7e8",
        lime: "#b4f34c",
        amber: "#ffc857",
        danger: "#ff6b7a"
      },
      boxShadow: {
        glow: "0 0 35px rgba(73, 215, 232, 0.12)"
      }
    }
  },
  plugins: []
};

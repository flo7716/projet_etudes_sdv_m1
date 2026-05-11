import { useState } from "react";

export default function PentestToolboxUI() {
  const [target, setTarget] = useState("http://dvwa");
  const [results, setResults] = useState("");
  const [loading, setLoading] = useState(false);

  const tools = [
    {
      name: "Nmap",
      description: "Scan réseau et détection de services",
      route: "/nmap?target=",
      color: "from-green-500 to-emerald-700",
    },
    {
      name: "Hydra",
      description: "Bruteforce login/password",
      route: "/hydra?target=",
      color: "from-red-500 to-rose-700",
    },
    {
      name: "Gobuster",
      description: "Découverte de répertoires web",
      route: "/gobuster?target=",
      color: "from-blue-500 to-cyan-700",
    },
    {
      name: "Nikto",
      description: "Audit web et vulnérabilités",
      route: "/nikto?target=",
      color: "from-yellow-500 to-orange-700",
    },
  ];

  async function runTool(route) {
    setLoading(true);
    setResults("Lancement du scan...");

    try {
      const response = await fetch(`${route}${target}`);
      const data = await response.json();

      setResults(JSON.stringify(data, null, 2));
    } catch (err) {
      setResults(`Erreur : ${err.message}`);
    }

    setLoading(false);
  }

  return (
    <div className="min-h-screen bg-zinc-950 text-white p-8">
      <div className="max-w-7xl mx-auto">

        {/* HEADER */}
        <div className="mb-10">
          <h1 className="text-5xl font-black tracking-tight mb-4">
            Pentest Toolbox
          </h1>

          <p className="text-zinc-400 text-lg max-w-3xl">
            Interface offensive Dockerisée basée sur Kali Linux,
            FastAPI et outils de pentest automatisés.
          </p>
        </div>

        {/* TARGET */}
        <div className="rounded-3xl border border-zinc-800 bg-zinc-900 p-6 mb-10 shadow-2xl">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-2xl font-bold">
              Cible
            </h2>

            <span className="text-xs bg-zinc-800 px-3 py-1 rounded-full text-zinc-400">
              docker network
            </span>
          </div>

          <input
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            placeholder="http://dvwa ou 172.18.0.2"
            className="w-full bg-zinc-950 border border-zinc-800 rounded-2xl px-4 py-4 outline-none focus:border-green-500 transition-all"
          />
        </div>

        {/* TOOLS */}
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-6 mb-10">
          {tools.map((tool) => (
            <div
              key={tool.name}
              className="rounded-3xl border border-zinc-800 bg-zinc-900 overflow-hidden shadow-2xl"
            >
              <div className={`h-2 bg-gradient-to-r ${tool.color}`} />

              <div className="p-6">
                <h2 className="text-2xl font-bold mb-2">
                  {tool.name}
                </h2>

                <p className="text-zinc-400 mb-6">
                  {tool.description}
                </p>

                <div className="bg-zinc-950 rounded-xl p-3 text-sm text-green-400 font-mono overflow-auto border border-zinc-800">
                  {tool.route}
                </div>

                <button
                  onClick={() => runTool(tool.route)}
                  disabled={loading}
                  className="mt-6 w-full rounded-2xl bg-white text-black py-3 font-semibold hover:scale-[1.02] transition-all disabled:opacity-50"
                >
                  {loading ? "Scan..." : "Lancer"}
                </button>
              </div>
            </div>
          ))}
        </div>

        {/* RESULTS */}
        <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">

          <div className="rounded-3xl border border-zinc-800 bg-zinc-900 p-6 shadow-2xl">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-2xl font-bold">
                Résultats
              </h2>

              <span className="text-xs bg-green-900/40 text-green-400 px-3 py-1 rounded-full border border-green-700">
                API active
              </span>
            </div>

            <div className="bg-black rounded-2xl border border-zinc-800 p-4 h-[500px] overflow-auto font-mono text-sm text-green-400 whitespace-pre-wrap">
              {results || "Aucun scan lancé."}
            </div>
          </div>

          {/* INFOS */}
          <div className="rounded-3xl border border-zinc-800 bg-zinc-900 p-6 shadow-2xl">

            <h2 className="text-2xl font-bold mb-6">
              Architecture
            </h2>

            <div className="space-y-4">

              <div className="bg-zinc-950 border border-zinc-800 rounded-2xl p-5">
                <div className="text-green-400 font-bold mb-2">
                  Frontend
                </div>

                <div className="text-zinc-400 text-sm">
                  React + Tailwind + Vite
                </div>
              </div>

              <div className="bg-zinc-950 border border-zinc-800 rounded-2xl p-5">
                <div className="text-blue-400 font-bold mb-2">
                  Backend
                </div>

                <div className="text-zinc-400 text-sm">
                  FastAPI + Uvicorn
                </div>
              </div>

              <div className="bg-zinc-950 border border-zinc-800 rounded-2xl p-5">
                <div className="text-red-400 font-bold mb-2">
                  Containers
                </div>

                <div className="text-zinc-400 text-sm">
                  Kali Linux + DVWA
                </div>
              </div>

              <div className="bg-zinc-950 border border-zinc-800 rounded-2xl p-5">
                <div className="text-yellow-400 font-bold mb-2">
                  Outils
                </div>

                <div className="text-zinc-400 text-sm">
                  Nmap, Hydra, Gobuster, Nikto
                </div>
              </div>

            </div>
          </div>

        </div>
      </div>
    </div>
  );
}
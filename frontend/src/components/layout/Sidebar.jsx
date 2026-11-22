import {
  LayoutDashboard,
  Monitor,
  Network,
  ShieldAlert,
  Siren,
  ShieldCheck,
  BarChart3,
  Settings,
  ChevronLeft,
  ChevronRight,
} from "lucide-react";
import { NavLink } from "react-router-dom";
import { useState } from "react";

const navigation = [
  {
    section: "OVERVIEW",
    items: [
      {
        name: "Dashboard",
        path: "/",
        icon: LayoutDashboard,
      },
    ],
  },
  {
    section: "MONITORING",
    items: [
      {
        name: "Devices",
        path: "/devices",
        icon: Monitor,
      },
      {
        name: "Network Activity",
        path: "/network",
        icon: Network,
      },
    ],
  },
  {
    section: "SECURITY",
    items: [
      {
        name: "Threat Detection",
        path: "/threats",
        icon: ShieldAlert,
      },
      {
        name: "Incidents",
        path: "/incidents",
        icon: Siren,
      },
    ],
  },
  {
    section: "RESPONSE",
    items: [
      {
        name: "Response Actions",
        path: "/response",
        icon: ShieldCheck,
      },
    ],
  },
  {
    section: "ANALYTICS",
    items: [
      {
        name: "Reports",
        path: "/reports",
        icon: BarChart3,
      },
    ],
  },
];

function Sidebar() {
  const [collapsed, setCollapsed] = useState(false);

  return (
    <aside
      className={`fixed left-0 top-0 z-50 hidden h-screen border-r border-slate-800 bg-slate-950 transition-all duration-300 md:block ${
        collapsed ? "w-20" : "w-64"
      }`}
    >
      {/* Logo */}
      <div className="flex h-16 items-center border-b border-slate-800 px-4">
        <div className="flex min-w-0 items-center gap-3">
          <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-blue-600">
            <ShieldCheck size={21} />
          </div>

          {!collapsed && (
            <div>
              <h1 className="text-lg font-bold tracking-wide text-white">
                ZeroGuard
              </h1>

              <p className="text-[10px] uppercase tracking-widest text-slate-500">
                Security Operations
              </p>
            </div>
          )}
        </div>
      </div>

      {/* Navigation */}
      <div className="h-[calc(100vh-128px)] overflow-y-auto px-3 py-4">
        {navigation.map((group) => (
          <div key={group.section} className="mb-5">
            {!collapsed && (
              <p className="mb-2 px-3 text-[10px] font-semibold tracking-widest text-slate-500">
                {group.section}
              </p>
            )}

            <div className="space-y-1">
              {group.items.map((item) => {
                const Icon = item.icon;

                return (
                  <NavLink
                    key={item.path}
                    to={item.path}
                    end={item.path === "/"}
                    title={collapsed ? item.name : undefined}
                    className={({ isActive }) =>
                      `group flex items-center rounded-lg px-3 py-2.5 text-sm transition-all ${
                        isActive
                          ? "bg-blue-600/15 text-blue-400"
                          : "text-slate-400 hover:bg-slate-900 hover:text-slate-100"
                      } ${collapsed ? "justify-center" : "gap-3"}`
                    }
                  >
                    {({ isActive }) => (
                      <>
                        <Icon
                          size={18}
                          className={
                            isActive
                              ? "text-blue-400"
                              : "text-slate-500 group-hover:text-slate-300"
                          }
                        />

                        {!collapsed && <span>{item.name}</span>}

                        {isActive && !collapsed && (
                          <span className="ml-auto h-1.5 w-1.5 rounded-full bg-blue-400" />
                        )}
                      </>
                    )}
                  </NavLink>
                );
              })}
            </div>
          </div>
        ))}
      </div>

      {/* Settings */}
      <div className="absolute bottom-0 left-0 right-0 border-t border-slate-800 bg-slate-950 p-3">
        <NavLink
          to="/settings"
          title={collapsed ? "Settings" : undefined}
          className={({ isActive }) =>
            `flex items-center rounded-lg px-3 py-2.5 text-sm transition ${
              isActive
                ? "bg-blue-600/15 text-blue-400"
                : "text-slate-400 hover:bg-slate-900 hover:text-slate-100"
            } ${collapsed ? "justify-center" : "gap-3"}`
          }
        >
          <Settings size={18} />
          {!collapsed && <span>Settings</span>}
        </NavLink>

        {/* Collapse Button */}
        <button
          onClick={() => setCollapsed(!collapsed)}
          className="mt-2 flex w-full items-center justify-center rounded-lg border border-slate-800 py-2 text-slate-500 transition hover:bg-slate-900 hover:text-slate-200"
          title={collapsed ? "Expand sidebar" : "Collapse sidebar"}
        >
          {collapsed ? (
            <ChevronRight size={17} />
          ) : (
            <>
              <ChevronLeft size={17} />
              <span className="ml-2 text-xs">Collapse</span>
            </>
          )}
        </button>
      </div>
    </aside>
  );
}

export default Sidebar;
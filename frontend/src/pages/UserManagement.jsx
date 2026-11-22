import { useEffect, useState } from "react";
import {
  CheckCircle2,
  Shield,
  UserCog,
  Users,
  XCircle,
  Trash2,
  RefreshCw,
  UserCheck,
} from "lucide-react";

import {
  getAdminUsers,
  updateUserRole,
  updateUserStatus,
  deleteAdminUser,
} from "../services/api";

import { useAuth } from "../context/AuthContext";

function UserManagement() {
  const { user: currentUser } = useAuth();

  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [actionLoading, setActionLoading] = useState(null);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");

  async function loadUsers() {
    try {
      setLoading(true);
      setError("");

      const response = await getAdminUsers();

      setUsers(response.users || []);
    } catch (err) {
      console.error("Failed to load users:", err);

      setError(
        err?.message || "Failed to load users"
      );
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadUsers();
  }, []);

  async function handleRoleChange(userId, newRole) {
    const targetUser = users.find(
      (item) => item.id === userId
    );

    if (!targetUser) {
      return;
    }

    if (currentUser?.id === userId) {
      setError(
        "You cannot change your own administrator role."
      );

      return;
    }

    try {
      setActionLoading(`role-${userId}`);
      setError("");
      setMessage("");

      await updateUserRole(userId, newRole);

      setMessage(
        `Role for @${targetUser.username} updated successfully.`
      );

      await loadUsers();
    } catch (err) {
      console.error("Role update failed:", err);

      setError(
        err?.message || "Failed to update user role"
      );
    } finally {
      setActionLoading(null);
    }
  }

  async function handleStatusChange(userId, newStatus) {
    const targetUser = users.find(
      (item) => item.id === userId
    );

    if (!targetUser) {
      return;
    }

    if (currentUser?.id === userId) {
      setError(
        "You cannot deactivate your own account."
      );

      return;
    }

    try {
      setActionLoading(`status-${userId}`);
      setError("");
      setMessage("");

      await updateUserStatus(userId, newStatus);

      setMessage(
        `Account status for @${targetUser.username} updated successfully.`
      );

      await loadUsers();
    } catch (err) {
      console.error("Status update failed:", err);

      setError(
        err?.message || "Failed to update user status"
      );
    } finally {
      setActionLoading(null);
    }
  }

  async function handleDelete(targetUser) {
    if (!targetUser) {
      return;
    }

    if (currentUser?.id === targetUser.id) {
      setError(
        "You cannot delete your own administrator account."
      );

      return;
    }

    const confirmed = window.confirm(
      `Delete user "${targetUser.username}" permanently?\n\nThis action cannot be undone.`
    );

    if (!confirmed) {
      return;
    }

    try {
      setActionLoading(
        `delete-${targetUser.id}`
      );

      setError("");
      setMessage("");

      await deleteAdminUser(targetUser.id);

      setMessage(
        `User @${targetUser.username} deleted successfully.`
      );

      await loadUsers();
    } catch (err) {
      console.error("User deletion failed:", err);

      setError(
        err?.message || "Failed to delete user"
      );
    } finally {
      setActionLoading(null);
    }
  }

  const totalUsers = users.length;

  const adminCount = users.filter(
    (user) => user.role === "admin"
  ).length;

  const activeCount = users.filter(
    (user) => user.status === "active"
  ).length;

  const inactiveCount = users.filter(
    (user) => user.status === "inactive"
  ).length;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
        <div>
          <div className="flex items-center gap-3">
            <div className="flex h-11 w-11 items-center justify-center rounded-xl bg-blue-500/10">
              <Users className="h-6 w-6 text-blue-400" />
            </div>

            <div>
              <h1 className="text-2xl font-semibold text-white">
                User Management
              </h1>

              <p className="mt-1 text-sm text-slate-400">
                Manage ZeroGuard security accounts and
                permissions.
              </p>
            </div>
          </div>
        </div>

        <button
          type="button"
          onClick={loadUsers}
          disabled={loading}
          className="inline-flex items-center justify-center gap-2 rounded-lg border border-slate-700 bg-slate-900 px-4 py-2.5 text-sm font-medium text-slate-200 transition hover:border-slate-600 hover:bg-slate-800 disabled:cursor-not-allowed disabled:opacity-50"
        >
          <RefreshCw
            className={`h-4 w-4 ${
              loading ? "animate-spin" : ""
            }`}
          />

          Refresh
        </button>
      </div>

      {/* Success message */}
      {message && (
        <div className="flex items-center gap-3 rounded-xl border border-emerald-500/20 bg-emerald-500/10 px-4 py-3">
          <CheckCircle2 className="h-5 w-5 text-emerald-400" />

          <p className="text-sm text-emerald-300">
            {message}
          </p>
        </div>
      )}

      {/* Error message */}
      {error && (
        <div className="flex items-center gap-3 rounded-xl border border-red-500/20 bg-red-500/10 px-4 py-3">
          <XCircle className="h-5 w-5 text-red-400" />

          <p className="text-sm text-red-300">
            {error}
          </p>
        </div>
      )}

      {/* Statistics */}
      <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-4">
        <StatCard
          icon={Users}
          label="Total Users"
          value={totalUsers}
        />

        <StatCard
          icon={Shield}
          label="Administrators"
          value={adminCount}
        />

        <StatCard
          icon={CheckCircle2}
          label="Active Accounts"
          value={activeCount}
        />

        <StatCard
          icon={XCircle}
          label="Inactive Accounts"
          value={inactiveCount}
        />
      </div>

      {/* Users table */}
      <div className="overflow-hidden rounded-2xl border border-slate-800 bg-slate-900/70">
        <div className="border-b border-slate-800 px-6 py-5">
          <div className="flex items-center gap-3">
            <UserCog className="h-5 w-5 text-cyan-400" />

            <div>
              <h2 className="font-semibold text-white">
                Registered Users
              </h2>

              <p className="mt-1 text-xs text-slate-500">
                Administrators can change roles, disable
                accounts, and remove users.
              </p>
            </div>
          </div>
        </div>

        {loading ? (
          <div className="flex min-h-[280px] items-center justify-center">
            <div className="text-center">
              <RefreshCw className="mx-auto h-8 w-8 animate-spin text-cyan-400" />

              <p className="mt-3 text-sm text-slate-400">
                Loading users...
              </p>
            </div>
          </div>
        ) : users.length === 0 ? (
          <div className="flex min-h-[280px] items-center justify-center">
            <div className="text-center">
              <Users className="mx-auto h-10 w-10 text-slate-600" />

              <p className="mt-3 text-sm text-slate-400">
                No users found.
              </p>
            </div>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[950px]">
              <thead>
                <tr className="border-b border-slate-800 bg-slate-950/50">
                  <th className="px-6 py-4 text-left text-xs font-semibold uppercase tracking-wider text-slate-500">
                    User
                  </th>

                  <th className="px-6 py-4 text-left text-xs font-semibold uppercase tracking-wider text-slate-500">
                    Email
                  </th>

                  <th className="px-6 py-4 text-left text-xs font-semibold uppercase tracking-wider text-slate-500">
                    Role
                  </th>

                  <th className="px-6 py-4 text-left text-xs font-semibold uppercase tracking-wider text-slate-500">
                    Status
                  </th>

                  <th className="px-6 py-4 text-left text-xs font-semibold uppercase tracking-wider text-slate-500">
                    Created
                  </th>

                  <th className="px-6 py-4 text-right text-xs font-semibold uppercase tracking-wider text-slate-500">
                    Actions
                  </th>
                </tr>
              </thead>

              <tbody className="divide-y divide-slate-800">
                {users.map((targetUser) => {
                  const isCurrentUser =
                    currentUser?.id === targetUser.id;

                  const roleLoading =
                    actionLoading ===
                    `role-${targetUser.id}`;

                  const statusLoading =
                    actionLoading ===
                    `status-${targetUser.id}`;

                  const deleteLoading =
                    actionLoading ===
                    `delete-${targetUser.id}`;

                  const selfProtected =
                    isCurrentUser;

                  return (
                    <tr
                      key={targetUser.id}
                      className={[
                        "transition hover:bg-slate-800/30",
                        isCurrentUser
                          ? "bg-blue-500/[0.03]"
                          : "",
                      ].join(" ")}
                    >
                      {/* User */}
                      <td className="px-6 py-5">
                        <div className="flex items-center gap-3">
                          <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-blue-500/10 text-sm font-semibold text-blue-400">
                            {(
                              targetUser.name ||
                              targetUser.username ||
                              "U"
                            )
                              .charAt(0)
                              .toUpperCase()}
                          </div>

                          <div>
                            <div className="flex items-center gap-2">
                              <p className="text-sm font-medium text-white">
                                {targetUser.name ||
                                  "Unnamed User"}
                              </p>

                              {isCurrentUser && (
                                <span className="inline-flex items-center gap-1 rounded-full border border-blue-500/20 bg-blue-500/10 px-2 py-0.5 text-[9px] font-semibold uppercase tracking-wider text-blue-400">
                                  <UserCheck className="h-3 w-3" />
                                  You
                                </span>
                              )}
                            </div>

                            <p className="mt-1 text-xs text-slate-500">
                              @{targetUser.username}
                            </p>
                          </div>
                        </div>
                      </td>

                      {/* Email */}
                      <td className="px-6 py-5">
                        <p className="text-sm text-slate-300">
                          {targetUser.email}
                        </p>
                      </td>

                      {/* Role */}
                      <td className="px-6 py-5">
                        <select
                          value={targetUser.role}
                          onChange={(event) =>
                            handleRoleChange(
                              targetUser.id,
                              event.target.value
                            )
                          }
                          disabled={
                            roleLoading ||
                            selfProtected
                          }
                          title={
                            selfProtected
                              ? "You cannot change your own administrator role."
                              : "Change user role"
                          }
                          className="rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-200 outline-none transition focus:border-blue-500 disabled:cursor-not-allowed disabled:opacity-40"
                        >
                          <option value="user">
                            User
                          </option>

                          <option value="admin">
                            Administrator
                          </option>
                        </select>
                      </td>

                      {/* Status */}
                      <td className="px-6 py-5">
                        <button
                          type="button"
                          onClick={() =>
                            handleStatusChange(
                              targetUser.id,
                              targetUser.status ===
                                "active"
                                ? "inactive"
                                : "active"
                            )
                          }
                          disabled={
                            statusLoading ||
                            selfProtected
                          }
                          title={
                            selfProtected
                              ? "You cannot deactivate your own account."
                              : "Change account status"
                          }
                          className="inline-flex items-center gap-2 rounded-full border border-slate-700 px-3 py-1.5 text-xs font-medium transition hover:border-slate-600 disabled:cursor-not-allowed disabled:opacity-40"
                        >
                          {targetUser.status ===
                          "active" ? (
                            <>
                              <span className="h-2 w-2 rounded-full bg-emerald-400" />

                              <span className="text-emerald-400">
                                Active
                              </span>
                            </>
                          ) : (
                            <>
                              <span className="h-2 w-2 rounded-full bg-red-400" />

                              <span className="text-red-400">
                                Inactive
                              </span>
                            </>
                          )}
                        </button>
                      </td>

                      {/* Created */}
                      <td className="px-6 py-5">
                        <p className="text-sm text-slate-400">
                          {formatDate(
                            targetUser.created_at
                          )}
                        </p>
                      </td>

                      {/* Actions */}
                      <td className="px-6 py-5 text-right">
                        <button
                          type="button"
                          onClick={() =>
                            handleDelete(targetUser)
                          }
                          disabled={
                            deleteLoading ||
                            selfProtected
                          }
                          title={
                            selfProtected
                              ? "You cannot delete your own account."
                              : "Delete user"
                          }
                          className="inline-flex items-center gap-2 rounded-lg border border-red-500/20 bg-red-500/5 px-3 py-2 text-xs font-medium text-red-400 transition hover:border-red-500/40 hover:bg-red-500/10 disabled:cursor-not-allowed disabled:opacity-40"
                        >
                          <Trash2 className="h-4 w-4" />

                          {deleteLoading
                            ? "Deleting..."
                            : "Delete"}
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Security notice */}
      <div className="rounded-xl border border-blue-500/20 bg-blue-500/5 p-5">
        <div className="flex gap-3">
          <Shield className="mt-0.5 h-5 w-5 shrink-0 text-blue-400" />

          <div>
            <h3 className="text-sm font-semibold text-blue-300">
              Administrator Security
            </h3>

            <p className="mt-1 text-xs leading-5 text-slate-400">
              User-management operations are protected by
              server-side administrator authorization. Your
              own administrator account is protected from
              accidental role changes, deactivation, and
              deletion.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}

function StatCard({
  icon: Icon,
  label,
  value,
}) {
  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-5">
      <div className="flex items-center justify-between">
        <div>
          <p className="text-xs font-medium uppercase tracking-wider text-slate-500">
            {label}
          </p>

          <p className="mt-2 text-2xl font-semibold text-white">
            {value}
          </p>
        </div>

        <div className="flex h-11 w-11 items-center justify-center rounded-xl bg-slate-800">
          <Icon className="h-5 w-5 text-cyan-400" />
        </div>
      </div>
    </div>
  );
}

function formatDate(value) {
  if (!value) {
    return "—";
  }

  const date = new Date(value);

  if (Number.isNaN(date.getTime())) {
    return value;
  }

  return date.toLocaleDateString("en-IN", {
    day: "2-digit",
    month: "short",
    year: "numeric",
  });
}

export default UserManagement;
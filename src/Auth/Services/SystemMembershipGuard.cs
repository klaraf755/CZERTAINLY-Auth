using Auth.Common.Exceptions;
using Auth.Models.Entities;

namespace Auth.Services
{
    /// <summary>
    /// Keeps the pairing between a system user and its role intact. A system user holds only the role seeded with it,
    /// and that role takes no other members: the pairing is the identity's whole permission boundary. Membership is
    /// editable from both directions, so both enforce the same rules.
    /// </summary>
    internal static class SystemMembershipGuard
    {
        /// <summary>
        /// Guards adding <paramref name="user"/> to <paramref name="role"/>; keeping an existing membership is always
        /// allowed. The one way a system user joins a role is the pairing made when it is seeded: it holds no role yet
        /// and the role is a system role with no members.
        /// </summary>
        public static void CheckAssignable(Role role, User user)
        {
            if ((role.Users ?? []).Any(member => member.Uuid == user.Uuid)) return;
            if (IsInitialPairing(role, user)) return;

            var systemMembers = SystemMembers(role);

            if (user.SystemUser)
            {
                throw new InvalidActionException($"System user '{user.Username}' holds only its own role and cannot be added to role '{role.Name}'.");
            }

            if (systemMembers.Count > 0)
            {
                throw new InvalidActionException($"Role '{role.Name}' belongs to a system user and cannot be assigned to user '{user.Username}'.");
            }
        }

        /// <summary>Requires permitted additions and retention of every system member.</summary>
        public static void CheckMembersReplaceable(Role role, IReadOnlyCollection<User> members)
        {
            foreach (var member in members) CheckAssignable(role, member);

            foreach (var systemMember in SystemMembers(role))
            {
                if (members.All(member => member.Uuid != systemMember.Uuid))
                {
                    throw new InvalidActionException($"Role '{role.Name}' belongs to system user '{systemMember.Username}', which cannot be removed from it.");
                }
            }
        }

        /// <summary>Guards replacing the roles of <paramref name="user"/> with <paramref name="retained"/>; an empty set detaches every role.</summary>
        public static void CheckRolesRetained(User user, IReadOnlyCollection<Role> retained)
        {
            if (!user.SystemUser) return;

            foreach (var held in user.Roles ?? [])
            {
                if (retained.All(role => role.Uuid != held.Uuid)) throw CannotRemove(held, user);
            }

            if (retained.Count > 1)
            {
                throw new InvalidActionException($"System user '{user.Username}' holds only its own role and cannot hold {retained.Count} roles.");
            }
        }

        /// <summary>Guards an explicit removal, which detaches without assigning anything the other rules could inspect.</summary>
        public static void CheckRoleRemovable(User user, Role role)
        {
            if (user.SystemUser && (user.Roles ?? []).Any(held => held.Uuid == role.Uuid)) throw CannotRemove(role, user);
        }

        private static bool IsInitialPairing(Role role, User user)
            => user.SystemUser && role.SystemRole && (user.Roles ?? []).Count == 0 && (role.Users ?? []).Count == 0;

        public static bool IsHeldBy(User user, Role role) => (user.Roles ?? []).Any(held => held.Uuid == role.Uuid);

        private static List<User> SystemMembers(Role role) => (role.Users ?? []).Where(user => user.SystemUser).ToList();

        private static InvalidActionException CannotRemove(Role role, User user)
            => new($"Role '{role.Name}' belongs to system user '{user.Username}' and cannot be removed from it.");
    }
}

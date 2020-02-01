const { AbilityBuilder, Ability } = require('@casl/ability');
const { rulesToQuery } = require('@casl/ability/extra');
const isRequestFromServer = require('feathers-hooks-common').isProvider(
  'server',
);
const { Forbidden } = require('@feathersjs/errors');

class NotAuthorized extends Forbidden {
  constructor(message='You are not authorized to make this request', data) {
    super(message, data);
  }
}

async function isAuthorized(context) {
  const {
    method, path, params
  } = context;
  const { user } = params;

  if (!user || isRequestFromServer(context)) {
    return context;
  }

  const ability = new Ability(context.params.rules, { subjectName: () => path });

  if (await ability.can(method, path)) {
    if (['find', 'patch', 'update', 'remove', 'get'].includes(method)) {
      const authQuery = rulesToQuery(ability, method, path, rule => (rule.inverted ? { $nor: [rule.conditions] } : rule.conditions));
      if (authQuery) {
        params.query = Object.assign(
          {},
          params.query,
          authQuery,
        );
      }
    }
  } else {
    throw new NotAuthorized();
  }

  return context;
}

function setPermission(permissionConfig) {
  return async (context) => {
    const { rules, can, cannot } = AbilityBuilder.extract();
    const { user } = context.params;
    const { path: servicePath } = context;

    if (isRequestFromServer(context) || !user) {
      return context;
    }

    const permissions = permissionConfig[user.role];

    await Promise.all(
      permissions.map(async (permission) => {
        permission.accessQuery = permission.accessQuery || (() => true);
        const method = permission.inverted ? cannot : can;
        method(
          permission.actions,
          servicePath,
          permission.fields,
          await permission.accessQuery({ user, context }),
        );
      }),
    );

    context.params.rules = rules;
    return context;
  };
}

module.exports = {
  isAuthorized,
  setPermission,
};

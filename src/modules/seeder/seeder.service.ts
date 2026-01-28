import { Injectable } from '@nestjs/common';
import { EntityManager } from 'typeorm';
import { User } from 'src/modules/users/entities/user.entity';
import { Role } from 'src/modules/roles/entities/role.entity';
import { Permission } from 'src/modules/roles/entities/permission.entity';
import { predefinedPermissions } from 'src/modules/seeder/data/permissions.data';
import { LoggerService } from 'src/lib/logger/logger.service';

@Injectable()
export class SeederService {
  constructor(
    private readonly entityManager: EntityManager,
    private readonly logger: LoggerService,
  ) { }

  async seed() {
    await Promise.all([this.#createRoles(), this.#createUsers()]);
  }

  async #createRoles() {
    this.logger.log('Creating roles...');
    const predefinedRoles = [
      {
        name: 'Admin',
        permissions: predefinedPermissions.Admin,
      },
      {
        name: 'Manager',
        permissions: predefinedPermissions.Manager,
      },
    ];

    await Promise.all(
      predefinedRoles.map(async roleData => {
        const roleExists = await this.entityManager.findOneBy(Role, {
          name: roleData.name,
        });

        if (!roleExists) {
          const role = this.entityManager.create(Role, { name: roleData.name });
          role.permissions = await Promise.all(
            roleData.permissions.map(async permData => {
              let permission = await this.entityManager.findOneBy(Permission, {
                name: permData.name,
              });
              if (!permission) {
                permission = this.entityManager.create(Permission, permData);
                await this.entityManager.save(permission);
              }
              return permission;
            }),
          );
          await this.entityManager.save(role);
        }
      }),
    );
  }

  async #createUsers() {
    this.logger.log('Creating users...');
    const roles = await this.entityManager.find(Role, {
      where: [{ name: 'Admin' }, { name: 'Manager' }],
    });
    const roleMap = roles.reduce<Record<string, Role>>((map, role) => {
      map[role.name] = role;
      return map;
    }, {});

    const users = [
      {
        fullName: 'Admin User',
        phoneNumber: '1234567890',
        email: 'admin@ekilie.com',
        password: 'admin@ekilie',
        role: roleMap['Admin'],
      },
      {
        fullName: 'Manager User',
        phoneNumber: '0987654321',
        email: 'manager@ekilie.com',
        password: 'manager@ekilie',
        role: roleMap['Manager'],
      },
    ];

    await Promise.all(
      users.map(async (userData: User) => {
        const userExists = await this.entityManager.findOneBy(User, [
          {
            email: userData.email,
          },
          { phoneNumber: userData.phoneNumber },
        ]);

        if (!userExists) {
          const user = this.entityManager.create(User, userData);
          await this.entityManager.save(user);
        } else {
          const updatedUser = userExists.update(userData);
          await this.entityManager.save(updatedUser);
        }
      }),
    );
  }
}

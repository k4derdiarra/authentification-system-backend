import {
  INestApplication,
  Injectable,
  OnModuleDestroy,
  OnModuleInit,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PrismaClient } from '@prisma/client';

@Injectable()
export class PrismaService
  extends PrismaClient
  implements OnModuleInit, OnModuleDestroy
{
  constructor(config: ConfigService) {
    super({
      datasources: {
        db: {
          url: config.get<string>('DATABASE_URL'),
        },
      },
      log:
        config.get<string>('NODE_ENV') !== 'TESTING' ? ['info', 'query'] : null,
    });
  }

  async onModuleInit() {
    await this.$connect();
  }

  async onModuleDestroy() {
    await this.$disconnect();
  }

  cleanDb() {
    return this.user.deleteMany();
  }

  deleteField<Type>(keys: string[], obj: Type): void {
    keys.forEach((key) => {
      if (obj[key] !== undefined) delete obj[key];
    });
  }
}

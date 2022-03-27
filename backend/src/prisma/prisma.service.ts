import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PrismaClient } from '@prisma/client';

@Injectable()
export class PrismaService extends PrismaClient {
  constructor(config: ConfigService) {
    super({
      datasources: {
        db: {
          url: config.get<string>('DATABASE_URL'),
        },
      },
    });
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

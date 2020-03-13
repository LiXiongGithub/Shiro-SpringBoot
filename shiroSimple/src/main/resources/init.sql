/*
SQLyog Ultimate v12.3.1 (64 bit)
MySQL - 5.7.25-log : Database - shiro
*********************************************************************
*/

/*!40101 SET NAMES utf8 */;

/*!40101 SET SQL_MODE=''*/;

/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;
CREATE DATABASE /*!32312 IF NOT EXISTS*/`shiro` /*!40100 DEFAULT CHARACTER SET utf8 */;

USE `shiro`;

/*Table structure for table `permission` */

DROP TABLE IF EXISTS `permission`;

CREATE TABLE `permission` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `name` varchar(100) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=12 DEFAULT CHARSET=utf8;

/*Data for the table `permission` */

insert  into `permission`(`id`,`name`) values 
(1,'addProduct'),
(2,'deleteProduct'),
(3,'editProduct'),
(4,'updateProduct'),
(5,'listProduct'),
(6,'addOrder'),
(7,'deleteOrder'),
(8,'editOrder'),
(9,'updateOrder'),
(10,'listOrder'),
(11,'/user/getMessage');

/*Table structure for table `role` */

DROP TABLE IF EXISTS `role`;

CREATE TABLE `role` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `name` varchar(100) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=4 DEFAULT CHARSET=utf8;

/*Data for the table `role` */

insert  into `role`(`id`,`name`) values 
(1,'admin'),
(2,'productManager'),
(3,'orderManager');

/*Table structure for table `role_permission` */

DROP TABLE IF EXISTS `role_permission`;

CREATE TABLE `role_permission` (
  `rid` bigint(20) NOT NULL,
  `pid` bigint(20) NOT NULL,
  PRIMARY KEY (`rid`,`pid`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

/*Data for the table `role_permission` */

insert  into `role_permission`(`rid`,`pid`) values 
(1,1),
(1,2),
(1,3),
(1,4),
(1,5),
(1,6),
(1,7),
(1,8),
(1,9),
(1,10),
(1,11),
(2,1),
(2,2),
(2,3),
(2,4),
(2,5),
(3,6),
(3,7),
(3,8),
(3,9),
(3,10);

/*Table structure for table `user` */

DROP TABLE IF EXISTS `user`;

CREATE TABLE `user` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `name` varchar(100) DEFAULT NULL,
  `password` varchar(100) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=4 DEFAULT CHARSET=utf8;

/*Data for the table `user` */

insert  into `user`(`id`,`name`,`password`) values 
(1,'zhang3','12345'),
(2,'li4','abcde'),
(3,'wang5','qwe');

/*Table structure for table `user_role` */

DROP TABLE IF EXISTS `user_role`;

CREATE TABLE `user_role` (
  `uid` bigint(20) NOT NULL,
  `rid` bigint(20) NOT NULL,
  PRIMARY KEY (`uid`,`rid`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

/*Data for the table `user_role` */

insert  into `user_role`(`uid`,`rid`) values 
(1,1),
(1,3),
(2,2),
(2,3);

/*Table structure for table `white_url` */

DROP TABLE IF EXISTS `white_url`;

CREATE TABLE `white_url` (
  `id` int(11) NOT NULL,
  `url` varchar(20) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

/*Data for the table `white_url` */

insert  into `white_url`(`id`,`url`) values 
(1,'/login'),
(2,'/guest/enter'),
(3,'/guest/getMessage');

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

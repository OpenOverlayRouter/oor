/*
 * lisp_int.c
 *
 * This file is part of LISP Mobile Node Implementation.
 * This is the LISP MN EID Interface module.
 * This module creates an "ethernet-like" interface
 * and registers the interface with the kernel 
 * 
 * Copyright (C) 2011 Cisco Systems, Inc, 2011. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * Please send any bug reports or fixes you make to the email address(es):
 *    LISP-MN developers <devel@lispmob.org>
 *
 * Written or modified by:
 *    Preethi Natarajan <prenatar@cisco.com>
 *
 */

#include "lisp_int.h"
#include <linux/string.h>

struct net_device   *lispint_dev;
struct lispint_priv {
    struct net_device_stats stats;
};

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Logical Inerface for LISP");

int lispint_open (struct net_device *dev)
{
    netif_start_queue(dev);
    return 0;
}

int lispint_stop (struct net_device *dev)
{
    netif_stop_queue(dev);
    return 0;
}

static netdev_tx_t lispint_xmit(struct sk_buff *skb, struct net_device *dev)
{

        dev->stats.tx_packets++;
        dev->stats.tx_bytes += skb->len;

        dev_kfree_skb(skb);
        printk(KERN_INFO "lisp_int: from xmit(): skb freed\n");
        return NETDEV_TX_OK;

}

static const struct net_device_ops    lispint_device_ops = {

    .ndo_open   =   lispint_open,
    .ndo_stop   =   lispint_stop,
    .ndo_start_xmit =   lispint_xmit,

};

static void lispint_setup(struct net_device *dev)
{
    struct lispint_priv *priv;

    /* Initialize dev structure */
    ether_setup(dev);

    dev->netdev_ops     =   &lispint_device_ops;
    dev->flags          |=  IFF_NOARP;

    priv   =   netdev_priv(dev);
    memset(priv, 0 , sizeof(struct lispint_priv));

}
static void __exit lispint_cleanup (void) {

    unregister_netdev(lispint_dev);
    printk(KERN_INFO "lisp_int: LISP interface unregistered");

    free_netdev(lispint_dev);

}

static int __init lispint_init(void)
{
    int err = 0;

    printk(KERN_INFO "lisp_int initialization");

    lispint_dev = alloc_netdev(sizeof(struct lispint_priv), "lmn%d", lispint_setup);
    if (!lispint_dev) {
        printk(KERN_INFO "lisp_int: No memory");
        return -ENOMEM;
    }

    /*
     * Register device with kernel
     */
    err = register_netdev(lispint_dev);

    if (err < 0) {
        printk(KERN_INFO "lisp_int: device registration failed");
        free_netdev(lispint_dev);
        return err;
    }

    printk(KERN_INFO "lisp_int: LISP interface registered");

    return 0;

}

/*
 * Module initialization
 */

/*
 * lispint_init_module()
 *
 * Main entry point for the module, performs all sub-initialization
 */
static int __init lispint_init_module (void)
{
  int result = 0;

  printk(KERN_INFO "lispint init module...\n");
  result    =   lispint_init();
  return result;
}

/*
 * lispint_exit_module()
 *
 * Cleanup routine, called when module is removed from the
 * kernel.
 */
static void __exit lispint_exit_module (void)
{

  printk(KERN_INFO "lispint module cleaning up...\n");
  lispint_cleanup();
}

module_init(lispint_init_module);
module_exit(lispint_exit_module);

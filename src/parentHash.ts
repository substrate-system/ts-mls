import type { Decoder } from './codec/tlsDecoder.js'
import { mapDecoders } from './codec/tlsDecoder.js'
import type { Encoder } from './codec/tlsEncoder.js'
import { contramapEncoders } from './codec/tlsEncoder.js'
import { decodeVarLenData, encodeVarLenData } from './codec/variableLength.js'
import type { Hash } from './crypto/hash.js'
import { InternalError } from './mlsError.js'
import type { Node, RatchetTree } from './ratchetTree.js'
import { findFirstNonBlankAncestor, removeLeaves } from './ratchetTree.js'
import { treeHash } from './treeHash.js'
import type {
    LeafIndex,
    NodeIndex
} from './treemath.js'
import {
    isLeaf,
    leafToNodeIndex,
    leafWidth,
    left,
    right,
    root,
    toLeafIndex,
    toNodeIndex,
} from './treemath.js'

import { constantTimeEqual } from './util/constantTimeCompare.js'

export interface ParentHashInput {
  encryptionKey: Uint8Array
  parentHash: Uint8Array
  originalSiblingTreeHash: Uint8Array
}

export const encodeParentHashInput: Encoder<ParentHashInput> = contramapEncoders(
    [encodeVarLenData, encodeVarLenData, encodeVarLenData],
    (i) => [i.encryptionKey, i.parentHash, i.originalSiblingTreeHash] as const,
)

export const decodeParentHashInput: Decoder<ParentHashInput> = mapDecoders(
    [decodeVarLenData, decodeVarLenData, decodeVarLenData],
    (encryptionKey, parentHash, originalSiblingTreeHash) => ({
        encryptionKey,
        parentHash,
        originalSiblingTreeHash,
    }),
)

function validateParentHashCoverage (parentIndices: number[], coverage: Record<number, number>): boolean {
    for (const index of parentIndices) {
        if ((coverage[index] ?? 0) !== 1) {
            return false
        }
    }
    return true
}

export async function verifyParentHashes (tree: RatchetTree, h: Hash): Promise<boolean> {
    const parentNodes = tree.reduce((acc, cur, index) => {
        if (cur !== undefined && cur.nodeType === 'parent') {
            return [...acc, index]
        } else return acc
    }, [] as number[])

    if (parentNodes.length === 0) return true

    const coverage = await parentHashCoverage(tree, h)

    return validateParentHashCoverage(parentNodes, coverage)
}

/**
 * Traverse tree from bottom up, verifying that all non-blank parent nodes are covered by exactly one chain
 */
function parentHashCoverage (tree: RatchetTree, h: Hash): Promise<Record<number, number>> {
    const leaves = tree.filter((_v, i) => isLeaf(toNodeIndex(i)))
    return leaves.reduce(
        async (acc, leafNode, leafIndex) => {
            if (leafNode === undefined) return acc

            let currentIndex = leafToNodeIndex(toLeafIndex(leafIndex))
            let updated = { ...(await acc) }

            const rootIndex = root(leafWidth(tree.length))

            while (currentIndex !== rootIndex) {
                const currentNode = tree[currentIndex]

                // skip blank nodes
                if (currentNode === undefined) {
                    continue
                }

                // parentHashNodeIndex is the node index where the nearest non blank ancestor was
                const [parentHash, parentHashNodeIndex] = await calculateParentHash(tree, currentIndex, h)

                if (parentHashNodeIndex === undefined) {
                    throw new InternalError('Reached root before completing parent hash coeverage')
                }

                const expectedParentHash = getParentHash(currentNode)

                if (expectedParentHash !== undefined && constantTimeEqual(parentHash, expectedParentHash)) {
                    const newCount = (updated[parentHashNodeIndex] ?? 0) + 1
                    updated = { ...updated, [parentHashNodeIndex]: newCount }
                } else {
                    // skip to next leaf
                    break
                }

                currentIndex = parentHashNodeIndex
            }

            return updated
        },
        Promise.resolve({} as Record<number, number>),
    )
}

function getParentHash (node: Node): Uint8Array | undefined {
    if (node.nodeType === 'parent') return node.parent.parentHash
    else if (node.leaf.leafNodeSource === 'commit') return node.leaf.parentHash
}

/**
 * Calculcates parent hash for a given node or leaf and returns the node index of the parent or undefined if the given node is the root node.
 */
export async function calculateParentHash (
    tree: RatchetTree,
    nodeIndex: NodeIndex,
    h: Hash,
): Promise<[Uint8Array, NodeIndex | undefined]> {
    const rootIndex = root(leafWidth(tree.length))
    if (nodeIndex === rootIndex) {
        return [new Uint8Array(), undefined]
    }

    const parentNodeIndex = findFirstNonBlankAncestor(tree, nodeIndex)

    const parentNode = tree[parentNodeIndex]

    if (parentNodeIndex === rootIndex && parentNode === undefined) {
        return [new Uint8Array(), parentNodeIndex]
    }

    const siblingIndex = nodeIndex < parentNodeIndex ? right(parentNodeIndex) : left(parentNodeIndex)

    if (parentNode === undefined || parentNode.nodeType === 'leaf') { throw new InternalError('Expected non-blank parent Node') }

    const removedUnmerged = removeLeaves(tree, parentNode.parent.unmergedLeaves as LeafIndex[])

    const originalSiblingTreeHash = await treeHash(removedUnmerged, siblingIndex, h)

    const input = {
        encryptionKey: parentNode.parent.hpkePublicKey,
        parentHash: parentNode.parent.parentHash,
        originalSiblingTreeHash,
    }

    return [await h.digest(encodeParentHashInput(input)), parentNodeIndex]
}
